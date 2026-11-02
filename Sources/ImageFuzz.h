// Sources/ImageFuzz.h
// lang: ObjC, file: ImageFuzz.h, target: iOS 15+, ImageIO + CoreGraphics
// ImageIO mutation fuzzer API.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, ImageFuzzFormat) {
    ImageFuzzFormatPNG  = 0,
    ImageFuzzFormatJPEG = 1,
    ImageFuzzFormatHEIC = 2,
    ImageFuzzFormatWebP = 3,
    ImageFuzzFormatGIF  = 4,
};

@interface ImageFuzzResult : NSObject
@property (nonatomic, copy)   NSString        *seedName;
@property (nonatomic, assign) ImageFuzzFormat  format;
@property (nonatomic, assign) NSUInteger       iteration;
@property (nonatomic, assign) BOOL             crashed;   // ObjC exception caught
@property (nonatomic, assign) BOOL             nullImage; // CGImage came back nil unexpectedly
@property (nonatomic, copy, nullable) NSString *exceptionDesc;
@property (nonatomic, copy, nullable) NSData   *reproducer; // mutated bytes that caused the hit
@end

/// Run the mutation fuzzer.
/// @param iterationsPerSeed   How many mutations per seed file (default: 200).
/// @param stopFlag            Pointer to a BOOL; set it to YES to abort the run mid-flight.
/// @param logBlock            Called on a background queue with progress lines.
/// @param completion          Called on main queue when done or stopped.
void ImageFuzzRun(NSUInteger iterationsPerSeed,
                  volatile BOOL *stopFlag,
                  void (^logBlock)(NSString *line),
                  void (^completion)(NSArray<ImageFuzzResult *> *hits));

NS_ASSUME_NONNULL_END
