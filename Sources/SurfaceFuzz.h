// Sources/SurfaceFuzz.h
// lang: ObjC, file: SurfaceFuzz.h, target: iOS 15+
// Multi-surface parser fuzzer: CoreText + AudioToolbox + NSKeyedUnarchiver

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, FuzzSurface) {
    FuzzSurfaceCoreText        = 0,
    FuzzSurfaceAudioToolbox    = 1,
    FuzzSurfaceUnarchiver      = 2,
};

@interface SurfaceFuzzResult : NSObject
@property (nonatomic, assign) FuzzSurface    surface;
@property (nonatomic, copy)   NSString      *seedName;
@property (nonatomic, assign) NSUInteger     iteration;
@property (nonatomic, assign) BOOL           crashed;
@property (nonatomic, copy, nullable) NSString *desc;
@property (nonatomic, copy, nullable) NSData   *reproducer;
@end

/// Run all non-ImageIO surfaces.
/// @param iterationsPerSeed   Mutations per seed (2000 for aggressive mode).
/// @param stopFlag            Set YES to abort.
/// @param logBlock            Progress lines, called on background queue.
/// @param completion          Main queue, called when all surfaces finish.
void SurfaceFuzzRun(NSUInteger iterationsPerSeed,
                    volatile BOOL *stopFlag,
                    void (^logBlock)(NSString *line),
                    void (^completion)(NSArray<SurfaceFuzzResult *> *hits));

NS_ASSUME_NONNULL_END
