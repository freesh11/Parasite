// Sources/ExceptionCatcher.h
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ObjCExceptionCatcher : NSObject
/// Runs the block. Returns nil on success, or an NSError describing the ObjC exception.
+ (nullable NSError *)runCatching:(void (NS_NOESCAPE ^)(void))block;
@end

NS_ASSUME_NONNULL_END
