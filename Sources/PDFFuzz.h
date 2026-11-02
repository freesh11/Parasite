// Sources/PDFFuzz.h
// lang: ObjC, file: PDFFuzz.h, target: iOS 15+
// PDFKit + CGPDFDocument parser fuzzer.
//
// Three parse paths targeted:
//   1. CGPDFDocument  — raw C API, no ObjC overhead.
//                       Hits: xref table parser, object stream decoder,
//                       stream filter chain (FlateDecode, LZWDecode, JBIG2).
//   2. PDFDocument    — PDFKit ObjC API.  Exercises annotation parsing,
//                       outline tree traversal, form field decode.
//   3. Embedded fonts — walks the /Resources /Font dict on each page,
//                       pulls /FontFile /FontFile2 /FontFile3 streams,
//                       passes raw bytes to CTFontManagerCreateFontDescriptorsFromData.
//                       This is the delivery path chollima uses.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, PDFFuzzSubsurface) {
    PDFFuzzSubsurfaceCGPDF        = 0,
    PDFFuzzSubsurfacePDFKit       = 1,
    PDFFuzzSubsurfaceEmbeddedFont = 2,
};

@interface PDFFuzzResult : NSObject
@property (nonatomic, assign) PDFFuzzSubsurface  subsurface;
@property (nonatomic, copy)   NSString          *seedName;
@property (nonatomic, assign) NSUInteger          iteration;
@property (nonatomic, assign) BOOL                crashed;
@property (nonatomic, copy, nullable) NSString   *desc;
@property (nonatomic, copy, nullable) NSData     *reproducer;
@end

/// Run all PDF surfaces concurrently.
/// @param iterationsPerSeed   Mutations per seed.
/// @param stopFlag            Set YES to abort.
/// @param logBlock            Progress lines, called on background queue.
/// @param completion          Main queue, called when all surfaces finish.
void PDFFuzzRun(NSUInteger iterationsPerSeed,
                volatile BOOL *stopFlag,
                void (^logBlock)(NSString *line),
                void (^completion)(NSArray<PDFFuzzResult *> *hits));

NS_ASSUME_NONNULL_END
