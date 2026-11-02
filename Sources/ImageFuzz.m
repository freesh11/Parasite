// Sources/ImageFuzz.m
// lang: ObjC, file: ImageFuzz.m, target: iOS 15+
// ImageIO mutation fuzzer engine.
//
// Pipeline per mutant:
//   1. flip/insert/delete random bytes in a copy of the seed
//   2. CGImageSourceCreateWithData — parses the container header
//   3. CGImageSourceCreateImageAtIndex — full decode into CGImage
//   4. CGBitmapContextCreate + CGContextDrawImage — force pixel unpack
//   5. CGImageCreateWithImageInRect — crop sub-region (exercises tiling paths)
//   6. catch NSException at each step; save reproducer on any crash or OOM signal
//
// Interesting signals:
//   - NSException thrown from CoreGraphics/ImageIO internals
//   - CGImageSourceGetStatus == kCGImageStatusInvalidData   (non-null source, null image: parser accepted but decode failed)
//   - CGImageSourceGetStatus == kCGImageStatusUnexpectedEOF
//   - nil CGImage returned from a non-empty, status-OK source  (unexpected; log it)
//   - imageSource nil but data non-empty (hard reject at header level — boring, skip)
//
// Not interesting (skip silently):
//   - nil imageSource (header totally unrecognised — mutant too mangled)
//   - kCGImageStatusIncomplete / kCGImageStatusReadingHeader — truncation noise

#import "ImageFuzz.h"
#import "ExceptionCatcher.h"
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>

// ── mutation helpers ──────────────────────────────────────────────────────────

static NSData *mutate(NSData *seed, NSUInteger iteration) {
    NSMutableData *m = [seed mutableCopy];
    uint8_t *bytes = (uint8_t *)m.mutableBytes;
    NSUInteger len  = m.length;
    if (len == 0) return m;

    // Seed the PRNG reproducibly from (iteration XOR seed length) so the same
    // iteration always produces the same mutant for a given seed file.
    uint64_t rng = (uint64_t)iteration ^ ((uint64_t)len << 32);
    #define NEXT_RAND() ({ rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; rng; })

    NSUInteger ops = 1 + (NSUInteger)(NEXT_RAND() % 12); // 1–12 mutations (aggressive)
    for (NSUInteger i = 0; i < ops; i++) {
        int op = (int)(NEXT_RAND() % 10);
        NSUInteger pos = (NSUInteger)(NEXT_RAND() % len);
        switch (op) {
            case 0: // flip a byte
                bytes[pos] ^= (uint8_t)(NEXT_RAND() & 0xFF);
                break;
            case 1: // set to boundary value
            {
                uint8_t boundaries[] = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF};
                bytes[pos] = boundaries[NEXT_RAND() % 6];
                break;
            }
            case 2: // zero a run (0–31 bytes)
            {
                NSUInteger run = (NSUInteger)(NEXT_RAND() % 32);
                NSUInteger end = MIN(pos + run, len);
                memset(bytes + pos, 0, end - pos);
                break;
            }
            case 3: // fill run with 0xFF
            {
                NSUInteger run = (NSUInteger)(NEXT_RAND() % 32);
                NSUInteger end = MIN(pos + run, len);
                memset(bytes + pos, 0xFF, end - pos);
                break;
            }
            case 4: // swap two bytes
            {
                NSUInteger pos2 = (NSUInteger)(NEXT_RAND() % len);
                uint8_t tmp = bytes[pos]; bytes[pos] = bytes[pos2]; bytes[pos2] = tmp;
                break;
            }
            case 5: // truncate after pos (forces unexpected-EOF paths)
                m.length = MAX(8, pos);
                bytes = (uint8_t *)m.mutableBytes;
                len   = m.length;
                break;
            case 6: // smash 4-byte big-endian field with 0xFFFFFFFF (overflow target)
                if (pos + 4 <= len) {
                    bytes[pos]=0xFF; bytes[pos+1]=0xFF; bytes[pos+2]=0xFF; bytes[pos+3]=0xFF;
                }
                break;
            case 7: // smash 4-byte big-endian field with 0x00000000
                if (pos + 4 <= len) {
                    bytes[pos]=0; bytes[pos+1]=0; bytes[pos+2]=0; bytes[pos+3]=0;
                }
                break;
            case 8: // smash 2-byte big-endian field with 0xFFFF
                if (pos + 2 <= len) { bytes[pos]=0xFF; bytes[pos+1]=0xFF; }
                break;
            case 9: // insert large-value 4-byte LE integer (width/height/stride overflow)
            {
                if (pos + 4 <= len) {
                    uint32_t v = (uint32_t)(NEXT_RAND() | 0x80000000); // always high bit set
                    memcpy(bytes + pos, &v, 4);
                }
                break;
            }
        }
    }
    #undef NEXT_RAND
    return m;
}

// ── decode pipeline ───────────────────────────────────────────────────────────

// Returns YES if this mutant produced a noteworthy signal.
// Fills outDesc with a human-readable description of what happened.
static BOOL tryDecode(NSData *data, NSString **outDesc) {
    __block BOOL hit = NO;
    __block NSString *desc = nil;

    NSError *err = [ObjCExceptionCatcher runCatching:^{
        CFDataRef cfdata = (__bridge CFDataRef)data;
        CGImageSourceRef src = CGImageSourceCreateWithData(cfdata, NULL);

        if (!src) return; // header unrecognised — skip

        CGImageSourceStatus status = CGImageSourceGetStatus(src);
        // Early-exit statuses that fire before deep parsing — not signal.
        // kCGImageStatusIncomplete(-1)    = truncated input, too common
        // kCGImageStatusReadingHeader(-2) = codec sniffing, pre-parse
        // kCGImageStatusUnknownType(-3)   = unrecognised magic bytes, pre-parse
        // kCGImageStatusInvalidData(-4)   = header rejected early, fires on ~all random mutations
        if (status == kCGImageStatusIncomplete    ||
            status == kCGImageStatusReadingHeader ||
            status == kCGImageStatusUnknownType   ||
            status == kCGImageStatusInvalidData) {
            CFRelease(src);
            return;
        }

        if (status == kCGImageStatusUnexpectedEOF) {
            // Parser got past header but hit EOF mid-parse — reaches deeper code.
            desc = [NSString stringWithFormat:@"ImageIO status=%ld (UnexpectedEOF)", (long)status];
            hit = YES;
            CFRelease(src);
            return;
        }

        // Full decode.
        // nil return here is the codec's normal error path on corrupt-but-accepted input — not signal.
        // Only exceptions and UnexpectedEOF are real. Skip nil silently.
        CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
        if (!img) { CFRelease(src); return; }

        size_t w = CGImageGetWidth(img);
        size_t h = CGImageGetHeight(img);

        if (w > 0 && h > 0 && w < 8192 && h < 8192) {
            // Force pixel unpack through bitmap context to exercise colour space / depth paths.
            CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
            size_t bpr = w * 4;
            void *buf = malloc(bpr * h);
            if (buf) {
                CGContextRef ctx = CGBitmapContextCreate(
                    buf, w, h, 8, bpr, cs,
                    kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
                if (ctx) {
                    CGContextDrawImage(ctx, CGRectMake(0, 0, (CGFloat)w, (CGFloat)h), img);
                    CFRelease(ctx);
                }
                free(buf);
            }
            CGColorSpaceRelease(cs);

            // Crop sub-region — exercises tiling / tile-decode paths.
            CGRect crop = CGRectMake(0, 0, (CGFloat)(w / 2 + 1), (CGFloat)(h / 2 + 1));
            CGImageRef cropped = CGImageCreateWithImageInRect(img, crop);
            if (cropped) CGImageRelease(cropped);
        }

        CGImageRelease(img);
        CFRelease(src);
    }];

    if (err) {
        NSString *name   = err.userInfo[@"name"]   ?: @"?";
        NSString *reason = err.userInfo[@"reason"] ?: @"?";
        desc = [NSString stringWithFormat:@"EXCEPTION %@: %@", name, reason];
        hit = YES;
    }

    if (outDesc) *outDesc = desc;
    return hit;
}

// ── corpus loader ─────────────────────────────────────────────────────────────

#import "CorpusData.h"

static NSString *formatExtension(ImageFuzzFormat fmt) {
    switch (fmt) {
        case ImageFuzzFormatPNG:  return @"png";
        case ImageFuzzFormatJPEG: return @"jpg";
        case ImageFuzzFormatHEIC: return @"heic";
        case ImageFuzzFormatWebP: return @"webp";
        case ImageFuzzFormatGIF:  return @"gif";
    }
    return @"bin";
}

@implementation ImageFuzzResult @end

// ── public entry point ────────────────────────────────────────────────────────

void ImageFuzzRun(NSUInteger iterationsPerSeed,
                  volatile BOOL *stopFlag,
                  void (^logBlock)(NSString *line),
                  void (^completion)(NSArray<ImageFuzzResult *> *hits)) {

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableArray<ImageFuzzResult *> *hits = [NSMutableArray array];
        NSMutableArray<NSDictionary *> *seeds = [NSMutableArray array];

        // Embedded corpus seeds — no bundle lookup needed.
        struct { const uint8_t *ptr; NSUInteger len; NSString *name; } table[] = {
            CORPUS_IMAGE_SEEDS
        };
        NSUInteger count = sizeof(table) / sizeof(table[0]);
        for (NSUInteger i = 0; i < count; i++) {
            NSData *data = [NSData dataWithBytes:table[i].ptr length:table[i].len];
            NSString *name = table[i].name;
            NSString *ext = [name pathExtension];
            ImageFuzzFormat fmt = ImageFuzzFormatPNG;
            if      ([ext isEqualToString:@"jpg"])  fmt = ImageFuzzFormatJPEG;
            else if ([ext isEqualToString:@"heic"]) fmt = ImageFuzzFormatHEIC;
            else if ([ext isEqualToString:@"webp"]) fmt = ImageFuzzFormatWebP;
            else if ([ext isEqualToString:@"gif"])  fmt = ImageFuzzFormatGIF;
            [seeds addObject:@{@"path": name, @"name": name, @"data": data, @"fmt": @(fmt)}];
        }

        logBlock([NSString stringWithFormat:
            @"ImageFuzz: loaded %lu seed files, %lu iterations each",
            (unsigned long)seeds.count, (unsigned long)iterationsPerSeed]);

        if (seeds.count == 0) {
            logBlock(@"ImageFuzz: ERROR — no embedded corpus seeds");
            dispatch_async(dispatch_get_main_queue(), ^{ completion(hits); });
            return;
        }

        NSUInteger totalIter = 0;
        NSUInteger hitCount  = 0;

        for (NSDictionary *seed in seeds) {
            if (stopFlag && *stopFlag) break;

            NSString *name = seed[@"name"];
            NSData   *data = seed[@"data"];
            ImageFuzzFormat fmt = (ImageFuzzFormat)[seed[@"fmt"] unsignedIntegerValue];

            logBlock([NSString stringWithFormat:
                @"ImageFuzz: [%@] starting %lu mutations",
                name, (unsigned long)iterationsPerSeed]);

            for (NSUInteger iter = 0; iter < iterationsPerSeed; iter++) {
                if (stopFlag && *stopFlag) break;

                NSData *mutant = mutate(data, iter);
                NSString *desc = nil;
                BOOL interesting = tryDecode(mutant, &desc);

                totalIter++;
                if (interesting) {
                    hitCount++;
                    ImageFuzzResult *r = [[ImageFuzzResult alloc] init];
                    r.seedName    = name;
                    r.format      = fmt;
                    r.iteration   = iter;
                    r.crashed     = (desc && [desc hasPrefix:@"EXCEPTION"]);
                    r.nullImage   = (desc && [desc containsString:@"nil"]);
                    r.exceptionDesc = desc;
                    r.reproducer  = mutant;
                    [hits addObject:r];

                    logBlock([NSString stringWithFormat:
                        @"ImageFuzz: HIT seed=%@ iter=%lu: %@",
                        name, (unsigned long)iter, desc]);

                    // Save reproducer to Documents/
                    NSString *repName = [NSString stringWithFormat:
                        @"reproducer_%@_iter%lu.%@",
                        [name stringByDeletingPathExtension],
                        (unsigned long)iter,
                        formatExtension(fmt)];
                    NSString *docs = [NSSearchPathForDirectoriesInDomains(
                        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
                    NSString *repPath = [docs stringByAppendingPathComponent:repName];
                    [mutant writeToFile:repPath atomically:YES];
                    logBlock([NSString stringWithFormat:@"ImageFuzz: saved reproducer → %@", repName]);
                }
            }

            logBlock([NSString stringWithFormat:
                @"ImageFuzz: [%@] done — %lu hits so far", name, (unsigned long)hitCount]);
        }

        logBlock([NSString stringWithFormat:
            @"ImageFuzz: COMPLETE — %lu iterations, %lu hits",
            (unsigned long)totalIter, (unsigned long)hitCount]);

        dispatch_async(dispatch_get_main_queue(), ^{ completion(hits); });
    });
}
