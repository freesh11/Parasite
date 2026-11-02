// Sources/ExceptionCatcher.m
#import "ExceptionCatcher.h"

@implementation ObjCExceptionCatcher

+ (nullable NSError *)runCatching:(void (NS_NOESCAPE ^)(void))block {
    @try {
        block();
        return nil;
    } @catch (NSException *exception) {
        NSMutableDictionary *info = [NSMutableDictionary dictionary];
        info[@"name"] = exception.name ?: @"(nil)";
        info[@"reason"] = exception.reason ?: @"(nil)";
        info[@"callStack"] = [exception.callStackSymbols componentsJoinedByString:@"\n"];
        return [NSError errorWithDomain:@"ObjCException" code:1 userInfo:info];
    }
}

@end
