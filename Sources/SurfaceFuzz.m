// Sources/SurfaceFuzz.m
// lang: ObjC, file: SurfaceFuzz.m, target: iOS 15+
#import "CorpusData.h"
// Multi-surface aggressive parser fuzzer.
//
// Surfaces:
//   CoreText  — CTFontCreateWithData / CTFontManagerCreateFontDescriptorsFromData
//               Targets: TTF, OTF, WOFF seed corpus.
//               Historical kills: CVE-2022-22666 (OOB read in CFF charstring),
//               CVE-2023-27930 (use-after-free in OpenType), countless stack overflows
//               in glyph rasterizer path.
//
//   AudioToolbox — AudioFileOpenWithCallbacks + AudioFileReadPacketData
//               Targets: MP3, M4A/AAC, AIFF, WAV, CAF seeds.
//               Parser runs in-process. Header fields like numFrames, sampleRate,
//               magic cookie size are prime integer-overflow targets.
//
//   NSKeyedUnarchiver — [NSKeyedUnarchiver unarchivedObjectOfClasses:fromData:]
//               Targets: crafted NSKeyedArchiver plists.
//               Class confusion bugs, recursive decode depth, cycle handling.
//               Lower probability but zero-cost to add.
//
// Mutation strategy: same deterministic byte-flip/boundary/truncation engine as
// ImageFuzz.m, but with format-aware header preservation to keep the seed
// recognisable long enough to reach deep parser state.
//
// All surfaces run concurrently on separate GCD queues (one per surface).
// Reproducers saved to Documents/ with surface prefix.

#import "SurfaceFuzz.h"
#import "ExceptionCatcher.h"
#import <CoreText/CoreText.h>
#import <AudioToolbox/AudioToolbox.h>

// ── shared mutation engine ────────────────────────────────────────────────────

// Header-preserving mutation: keeps the first `headerBytes` bytes intact,
// mutates the rest. Forces parser to reach deep decode state before hitting
// corrupted data.
static NSData *mutatePreserveHeader(NSData *seed, NSUInteger iter, NSUInteger headerBytes) {
    NSMutableData *m = [seed mutableCopy];
    uint8_t *bytes = (uint8_t *)m.mutableBytes;
    NSUInteger len  = m.length;
    if (len <= headerBytes) {
        // too short to preserve — fall through to full mutation
        headerBytes = 0;
    }

    uint64_t rng = (uint64_t)iter ^ ((uint64_t)len << 32) ^ 0xDEADC0FFEE;
    #define RAND() ({ rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; rng; })

    NSUInteger ops = 1 + (NSUInteger)(RAND() % 8); // 1–8 mutations
    for (NSUInteger i = 0; i < ops; i++) {
        // Only mutate past the preserved header region.
        NSUInteger range = len - headerBytes;
        if (range == 0) break;
        NSUInteger pos = headerBytes + (NSUInteger)(RAND() % range);

        int op = (int)(RAND() % 7);
        switch (op) {
            case 0: bytes[pos] ^= (uint8_t)(RAND() & 0xFF); break;
            case 1: { uint8_t b[] = {0,1,0x7F,0x80,0xFE,0xFF}; bytes[pos] = b[RAND()%6]; break; }
            case 2: { NSUInteger e = MIN(pos+16, len); memset(bytes+pos,0,e-pos); break; }
            case 3: { NSUInteger e = MIN(pos+16, len); memset(bytes+pos,0xFF,e-pos); break; }
            case 4: { // write 4-byte big-endian 0xFFFFFFFF at pos (overflow field)
                if (pos + 4 <= len) { bytes[pos]=0xFF; bytes[pos+1]=0xFF; bytes[pos+2]=0xFF; bytes[pos+3]=0xFF; }
                break;
            }
            case 5: { // write 4-byte big-endian 0 (zero-length / null field)
                if (pos + 4 <= len) { bytes[pos]=0; bytes[pos+1]=0; bytes[pos+2]=0; bytes[pos+3]=0; }
                break;
            }
            case 6: // truncate to mid-body
                m.length = MAX(headerBytes + 4, pos);
                bytes = (uint8_t *)m.mutableBytes;
                len   = m.length;
                break;
        }
    }
    #undef RAND
    return m;
}

// ── TTF structure-aware mutation ──────────────────────────────────────────────
// Targets the sfnt directory layer: numTables, table directory entries,
// head.checkSumAdjustment, and loca.indexToLocFormat.
// Keeps the 4-byte sfnt version intact so CTFontManagerCreateFontDescriptorsFromData
// still attempts parsing, then corrupts one structural field per call.
//
// sfnt layout:
//   [0]  4B  sfntVersion  (preserved)
//   [4]  2B  numTables    (target)
//   [6]  2B  searchRange
//   [8]  2B  entrySelector
//  [10]  2B  rangeShift
//  [12]  N×16B  table directory entries:
//           [+0]  4B  tag
//           [+4]  4B  checksum
//           [+8]  4B  offset
//          [+12]  4B  length
//
// head table (once offset located from directory):
//   [+8]   4B  checkSumAdjustment  (target — must be 0xB1B0AFBA minus sum of all)
//
// loca table:
//   [+2]   2B  indexToLocFormat    (0=short, 1=long — corrupt to 0xFF triggers wrong path)

static NSData *mutateTTFAware(NSData *seed, NSUInteger iter) {
    if (seed.length < 12 + 16) return seed; // not enough to be a valid sfnt

    NSMutableData *m = [seed mutableCopy];
    uint8_t *b  = (uint8_t *)m.mutableBytes;
    NSUInteger len = m.length;

    // Parse numTables from the sfnt header
    uint16_t numTables = (uint16_t)((b[4] << 8) | b[5]);
    // Clamp to reasonable range so we don't walk off the buffer
    if (numTables == 0 || numTables > 64) numTables = 10;

    // Deterministic per-iter operation selection
    uint64_t rng = (uint64_t)iter ^ 0xF077DEAD;
    #define RNG() ({ rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; rng; })

    int op = (int)(RNG() % 6);
    switch (op) {
        case 0: {
            // Corrupt numTables — write a boundary value
            uint16_t vals[] = {0, 1, 0x00FF, 0xFFFF, 0x7FFF, 0x0100};
            uint16_t v = vals[RNG() % 6];
            b[4] = (v >> 8) & 0xFF;
            b[5] = v & 0xFF;
            break;
        }
        case 1: {
            // Corrupt a random table directory entry's offset field (directory[i]+8)
            uint16_t tidx = (uint16_t)(RNG() % numTables);
            NSUInteger entryOffset = 12 + tidx * 16 + 8; // offset field
            if (entryOffset + 4 <= len) {
                uint32_t badOffsets[] = {0, 0xFFFFFFFF, 0x7FFFFFFF, (uint32_t)len, (uint32_t)(len + 1)};
                uint32_t v = badOffsets[RNG() % 5];
                b[entryOffset+0] = (v >> 24) & 0xFF;
                b[entryOffset+1] = (v >> 16) & 0xFF;
                b[entryOffset+2] = (v >>  8) & 0xFF;
                b[entryOffset+3] = v & 0xFF;
            }
            break;
        }
        case 2: {
            // Corrupt a table directory entry's length field (directory[i]+12)
            uint16_t tidx = (uint16_t)(RNG() % numTables);
            NSUInteger entryOffset = 12 + tidx * 16 + 12; // length field
            if (entryOffset + 4 <= len) {
                uint32_t badLens[] = {0, 0xFFFFFFFF, 0x7FFFFFFF, 1};
                uint32_t v = badLens[RNG() % 4];
                b[entryOffset+0] = (v >> 24) & 0xFF;
                b[entryOffset+1] = (v >> 16) & 0xFF;
                b[entryOffset+2] = (v >>  8) & 0xFF;
                b[entryOffset+3] = v & 0xFF;
            }
            break;
        }
        case 3: {
            // Find 'head' table and corrupt checkSumAdjustment (+8)
            for (uint16_t i = 0; i < numTables && i < 64; i++) {
                NSUInteger eo = 12 + i * 16;
                if (eo + 16 > len) break;
                if (b[eo]==0x68 && b[eo+1]==0x65 && b[eo+2]==0x61 && b[eo+3]==0x64) { // 'head'
                    uint32_t headOff = ((uint32_t)b[eo+8]<<24)|((uint32_t)b[eo+9]<<16)|
                                       ((uint32_t)b[eo+10]<<8)|b[eo+11];
                    if (headOff + 12 <= len) {
                        // checkSumAdjustment is at head+8..+11
                        uint32_t v = (uint32_t)(RNG() & 0xFFFFFFFF);
                        b[headOff+8]  = (v >> 24) & 0xFF;
                        b[headOff+9]  = (v >> 16) & 0xFF;
                        b[headOff+10] = (v >>  8) & 0xFF;
                        b[headOff+11] = v & 0xFF;
                    }
                    break;
                }
            }
            break;
        }
        case 4: {
            // Find 'loca' table and corrupt indexToLocFormat (+2 into table body)
            for (uint16_t i = 0; i < numTables && i < 64; i++) {
                NSUInteger eo = 12 + i * 16;
                if (eo + 16 > len) break;
                if (b[eo]==0x6C && b[eo+1]==0x6F && b[eo+2]==0x63 && b[eo+3]==0x61) { // 'loca'
                    // loca body is just the offset array — indexToLocFormat lives in 'head'
                    // instead corrupt the loca offset at position 0 or 1
                    uint32_t locaOff = ((uint32_t)b[eo+8]<<24)|((uint32_t)b[eo+9]<<16)|
                                       ((uint32_t)b[eo+10]<<8)|b[eo+11];
                    if (locaOff + 4 <= len) {
                        // Write a wild loca entry
                        uint32_t bad[] = {0xFFFFFFFF, 0x7FFFFFFF};
                        uint32_t v = bad[RNG() % 2];
                        b[locaOff+0] = (v >> 24) & 0xFF;
                        b[locaOff+1] = (v >> 16) & 0xFF;
                        b[locaOff+2] = (v >>  8) & 0xFF;
                        b[locaOff+3] = v & 0xFF;
                    }
                    break;
                }
            }
            break;
        }
        case 5: {
            // Corrupt head.indexToLocFormat directly (head+50)
            for (uint16_t i = 0; i < numTables && i < 64; i++) {
                NSUInteger eo = 12 + i * 16;
                if (eo + 16 > len) break;
                if (b[eo]==0x68 && b[eo+1]==0x65 && b[eo+2]==0x61 && b[eo+3]==0x64) {
                    uint32_t headOff = ((uint32_t)b[eo+8]<<24)|((uint32_t)b[eo+9]<<16)|
                                       ((uint32_t)b[eo+10]<<8)|b[eo+11];
                    // head table size is 54 bytes; indexToLocFormat at +50..+51
                    if (headOff + 52 <= len) {
                        uint16_t badVals[] = {0xFFFF, 2, 0x7FFF, 0xFF};
                        uint16_t v = badVals[RNG() % 4];
                        b[headOff+50] = (v >> 8) & 0xFF;
                        b[headOff+51] = v & 0xFF;
                    }
                    break;
                }
            }
            break;
        }
    }
    #undef RNG
    return m;
}

// ── CoreText surface ──────────────────────────────────────────────────────────

// Registered callback read: iOS requires AudioFile to have real seekable data.
// We wrap NSData in a simple callback.
typedef struct { NSData *data; NSUInteger pos; } AudioCallbackCtx;

static OSStatus audioRead(void *ctx, SInt64 pos, UInt32 requestCount,
                          void *buffer, UInt32 *actualCount) {
    AudioCallbackCtx *c = (AudioCallbackCtx *)ctx;
    if ((NSUInteger)pos >= c->data.length) { *actualCount = 0; return noErr; }
    NSUInteger avail = c->data.length - (NSUInteger)pos;
    *actualCount = (UInt32)MIN((NSUInteger)requestCount, avail);
    memcpy(buffer, (const uint8_t *)c->data.bytes + pos, *actualCount);
    return noErr;
}
static SInt64 audioGetSize(void *ctx) {
    return (SInt64)((AudioCallbackCtx *)ctx)->data.length;
}
static OSStatus audioSetSize(void *ctx, SInt64 size) { return kAudioFileNotOpenError; }

// Try to load a font from raw data. Returns YES if any interesting signal fires.
// Hit conditions:
//   - ObjC exception at any parse stage (existing)
//   - CTFontManagerCreateFontDescriptorsFromData returns non-NULL but CTFontCreateWithFontDescriptor
//     returns NULL — descriptor parsed but instantiation faulted (NEW)
//   - CTFontCreateWithName path: exercises the name table parser directly (NEW)
//   - CTFontGetAdvancesForGlyphs returns 0 for every glyph on a font that claims glyphs exist (NEW)
static BOOL tryCoreTextFont(NSData *data, NSString **outDesc) {
    __block BOOL hit = NO;
    __block NSString *desc = nil;

    NSError *err = [ObjCExceptionCatcher runCatching:^{
        CFDataRef cfdata = (__bridge CFDataRef)data;

        // Path 1: CTFontManagerCreateFontDescriptorsFromData
        // Runs the full font validation pipeline including sfnt table parsing.
        CFArrayRef descs = CTFontManagerCreateFontDescriptorsFromData(cfdata);

        if (!descs || CFArrayGetCount(descs) == 0) {
            // Font rejected outright — not a hit (pre-parse rejection).
            if (descs) CFRelease(descs);
            return;
        }

        // Path 2: Instantiate — triggers metric/glyph table parsing.
        CTFontDescriptorRef fd = (CTFontDescriptorRef)CFArrayGetValueAtIndex(descs, 0);
        CTFontRef font = CTFontCreateWithFontDescriptor(fd, 12.0f, NULL);
        if (!font) {
            // Descriptor parsed OK but instantiation failed — interesting.
            desc = @"CTFontCreateWithFontDescriptor returned NULL (descriptor parsed, instantiate failed)";
            hit = YES;
            CFRelease(descs);
            return;
        }
        CFRelease(descs);

        // Path 3: Glyph rects — exercises CFF charstring / TT glyf parser.
        CGGlyph glyphs[256];
        UniChar chars[256];
        for (int i = 0; i < 256; i++) chars[i] = (UniChar)i;
        CTFontGetGlyphsForCharacters(font, chars, glyphs, 256);
        CGRect rects[256];
        CTFontGetBoundingRectsForGlyphs(font, kCTFontOrientationDefault, glyphs, rects, 256);

        // Path 4: Advances — exercises hmtx/vmtx; zero advances on a usable font is suspicious.
        CGSize advances[256] = {};
        double totalAdvance = CTFontGetAdvancesForGlyphs(font, kCTFontOrientationDefault,
                                                          glyphs, advances, 256);
        CGFloat numGlyphs = CTFontGetGlyphCount(font);
        if (numGlyphs > 0 && totalAdvance == 0.0) {
            desc = @"CTFontGetAdvancesForGlyphs zero advance on font with glyphs (hmtx corrupt?)";
            hit = YES;
        }

        // Path 5: CTFontCreateWithName — exercises the 'name' table parser (ID 4 = full name).
        CFStringRef fullName = CTFontCopyFullName(font);
        if (fullName) {
            CTFontRef font2 = CTFontCreateWithName(fullName, 12.0f, NULL);
            if (!font2) {
                // Name round-trip failed — name table corrupt or mismatched.
                if (!hit) desc = @"CTFontCreateWithName failed on CTFontCopyFullName result (name table?)";
                hit = YES;
            } else {
                CFRelease(font2);
            }
            CFRelease(fullName);
        }

        CFRelease(font);
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

// ── AudioToolbox surface ──────────────────────────────────────────────────────

static BOOL tryAudioFile(NSData *data, NSString **outDesc) {
    __block BOOL hit = NO;
    __block NSString *desc = nil;

    NSError *err = [ObjCExceptionCatcher runCatching:^{
        AudioCallbackCtx ctx = { .data = data, .pos = 0 };
        AudioFileID af = NULL;

        // kAudioFileReadPermission — read-only probe, won't write anything.
        // Pass 0 as fileTypeHint so AudioFile sniffs the format.
        OSStatus st = AudioFileOpenWithCallbacks(
            &ctx,
            audioRead,
            NULL,         // write callback — nil, read-only
            audioGetSize,
            audioSetSize,
            0,            // inFileTypeHint — 0 = sniff
            &af);

        if (st != noErr || !af) return;

        // Read file property: data format. Exercises format-specific header parsing.
        AudioStreamBasicDescription asbd = {};
        UInt32 propSize = sizeof(asbd);
        AudioFileGetProperty(af, kAudioFilePropertyDataFormat, &propSize, &asbd);

        // Read packet count — integer overflow target in many parsers.
        UInt64 pktCount = 0;
        propSize = sizeof(pktCount);
        AudioFileGetProperty(af, kAudioFilePropertyAudioDataPacketCount, &propSize, &pktCount);

        // Try reading up to 16 packets of audio data — exercises codec layer.
        if (pktCount > 0) {
            UInt32 numPkts = 16;
            UInt32 bytesToRead = 65536;
            void *buf = malloc(bytesToRead);
            if (buf) {
                AudioFileReadPacketData(af, false, &bytesToRead, NULL, 0, &numPkts, buf);
                free(buf);
            }
        }

        AudioFileClose(af);
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

// ── NSKeyedUnarchiver surface ─────────────────────────────────────────────────

static BOOL tryUnarchiver(NSData *data, NSString **outDesc) {
    __block BOOL hit = NO;
    __block NSString *desc = nil;

    // Allowed classes: common Foundation classes that participate in decode graphs.
    // Deliberately broad — we want to reach as many deserialization paths as possible.
    NSSet *allowedClasses = [NSSet setWithArray:@[
        [NSString class], [NSNumber class], [NSData class], [NSDate class],
        [NSArray class],  [NSDictionary class], [NSSet class], [NSURL class],
        [NSError class],  [NSValue class],
    ]];

    NSError *err = [ObjCExceptionCatcher runCatching:^{
        NSError *decErr = nil;
        id obj = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                     fromData:data
                                                        error:&decErr];
        // A nil result with no exception means the plist was rejected early — not interesting.
        // A non-nil result that exercises deep graph traversal is what we want.
        (void)obj;
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

// ── per-surface run loop ──────────────────────────────────────────────────────

typedef BOOL (*TryFn)(NSData *, NSString **);

static void runSurface(FuzzSurface surface,
                       NSString *label,
                       TryFn tryFn,
                       NSArray<NSString *> *extensions,
                       NSUInteger headerPreserveBytes,
                       NSUInteger iters,
                       volatile BOOL *stopFlag,
                       void (^logBlock)(NSString *),
                       NSMutableArray<SurfaceFuzzResult *> *hits,
                       dispatch_semaphore_t done) {

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableArray<NSDictionary *> *seeds = [NSMutableArray array];

        // Embedded corpus seeds selected by surface type.
        if (surface == FuzzSurfaceCoreText) {
            struct { const uint8_t *ptr; NSUInteger len; NSString *name; } t[] = { CORPUS_SURFACE_SEEDS };
            for (NSUInteger i = 0; i < sizeof(t)/sizeof(t[0]); i++) {
                NSString *ext = [t[i].name pathExtension];
                if ([ext isEqualToString:@"ttf"] || [ext isEqualToString:@"otf"] ||
                    [ext isEqualToString:@"woff"]) {
                    [seeds addObject:@{@"name": t[i].name,
                                       @"data": [NSData dataWithBytes:t[i].ptr length:t[i].len]}];
                }
            }
        } else if (surface == FuzzSurfaceAudioToolbox) {
            struct { const uint8_t *ptr; NSUInteger len; NSString *name; } t[] = { CORPUS_SURFACE_SEEDS };
            for (NSUInteger i = 0; i < sizeof(t)/sizeof(t[0]); i++) {
                NSString *ext = [t[i].name pathExtension];
                if ([ext isEqualToString:@"wav"] || [ext isEqualToString:@"aiff"] ||
                    [ext isEqualToString:@"mp3"] || [ext isEqualToString:@"m4a"] ||
                    [ext isEqualToString:@"caf"]) {
                    [seeds addObject:@{@"name": t[i].name,
                                       @"data": [NSData dataWithBytes:t[i].ptr length:t[i].len]}];
                }
            }
        } else { // Unarchiver
            struct { const uint8_t *ptr; NSUInteger len; NSString *name; } t[] = { CORPUS_SURFACE_SEEDS };
            for (NSUInteger i = 0; i < sizeof(t)/sizeof(t[0]); i++) {
                NSString *ext = [t[i].name pathExtension];
                if ([ext isEqualToString:@"plist"] || [ext isEqualToString:@"nsa"]) {
                    [seeds addObject:@{@"name": t[i].name,
                                       @"data": [NSData dataWithBytes:t[i].ptr length:t[i].len]}];
                }
            }
        }

        // Validate seeds: for CoreText, discard any seed that CTFontManagerCreateFontDescriptorsFromData
        // already rejects unmodified. A pre-broken seed produces 100% pre-parse rejections —
        // mutateTTFAware can't help when the container is already rejected. Only valid seeds reach
        // deep parser state on mutation.
        if (surface == FuzzSurfaceCoreText) {
            NSMutableArray *valid = [NSMutableArray array];
            for (NSDictionary *seed in seeds) {
                NSData *d = seed[@"data"];
                CFArrayRef check = CTFontManagerCreateFontDescriptorsFromData((__bridge CFDataRef)d);
                if (check && CFArrayGetCount(check) > 0) {
                    [valid addObject:seed];
                    CFRelease(check);
                } else {
                    if (check) CFRelease(check);
                    logBlock([NSString stringWithFormat:@"%@: DROPPED broken seed %@ (rejected unmodified)",
                        label, seed[@"name"]]);
                }
            }
            seeds = valid;
        }

        logBlock([NSString stringWithFormat:@"%@: %lu seeds × %lu iter",
            label, (unsigned long)seeds.count, (unsigned long)iters]);

        if (seeds.count == 0) {
            logBlock([NSString stringWithFormat:@"%@: WARNING no seeds found (all pre-broken — replace corpus)", label]);
            dispatch_semaphore_signal(done);
            return;
        }

        NSUInteger hitCount = 0;
        for (NSDictionary *seed in seeds) {
            if (stopFlag && *stopFlag) break;
            NSString *name = seed[@"name"];
            NSData   *data = seed[@"data"];

            // TTF/OTF on CoreText: always use structure-aware mutation — random byte
            // flipping hits pre-parse rejection before any interesting table code runs.
            NSString *seedExt = [name pathExtension];
            BOOL isTTF = (surface == FuzzSurfaceCoreText &&
                          ([seedExt isEqualToString:@"ttf"] || [seedExt isEqualToString:@"otf"]));

            for (NSUInteger iter = 0; iter < iters; iter++) {
                if (stopFlag && *stopFlag) break;
                NSData *mutant = isTTF
                    ? mutateTTFAware(data, iter)
                    : mutatePreserveHeader(data, iter, headerPreserveBytes);
                NSString *desc = nil;
                BOOL hit = tryFn(mutant, &desc);

                if (hit) {
                    hitCount++;
                    SurfaceFuzzResult *r = [[SurfaceFuzzResult alloc] init];
                    r.surface    = surface;
                    r.seedName   = name;
                    r.iteration  = iter;
                    r.crashed    = (desc && [desc hasPrefix:@"EXCEPTION"]);
                    r.desc       = desc;
                    r.reproducer = mutant;
                    @synchronized(hits) { [hits addObject:r]; }

                    logBlock([NSString stringWithFormat:
                        @"%@: HIT seed=%@ iter=%lu: %@",
                        label, name, (unsigned long)iter, desc]);

                    // Save reproducer
                    NSString *docs = [NSSearchPathForDirectoriesInDomains(
                        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
                    NSString *repName = [NSString stringWithFormat:
                        @"repr_%@_%@_iter%lu.bin", label,
                        [name stringByDeletingPathExtension], (unsigned long)iter];
                    [mutant writeToFile:[docs stringByAppendingPathComponent:repName]
                             atomically:YES];
                }
            }

            logBlock([NSString stringWithFormat:@"%@: [%@] done — %lu hits so far",
                label, name, (unsigned long)hitCount]);
        }

        logBlock([NSString stringWithFormat:@"%@: COMPLETE — %lu hits", label, (unsigned long)hitCount]);
        dispatch_semaphore_signal(done);
    });
}

// ── public entry ──────────────────────────────────────────────────────────────

@implementation SurfaceFuzzResult @end

void SurfaceFuzzRun(NSUInteger iterationsPerSeed,
                    volatile BOOL *stopFlag,
                    void (^logBlock)(NSString *line),
                    void (^completion)(NSArray<SurfaceFuzzResult *> *hits)) {

    NSMutableArray<SurfaceFuzzResult *> *hits = [NSMutableArray array];

    dispatch_semaphore_t sem1 = dispatch_semaphore_create(0);
    dispatch_semaphore_t sem2 = dispatch_semaphore_create(0);
    dispatch_semaphore_t sem3 = dispatch_semaphore_create(0);

    // CoreText — font files, preserve first 12 bytes (sfnt header / WOFF magic)
    runSurface(FuzzSurfaceCoreText, @"CoreText",
               tryCoreTextFont,
               @[@"ttf", @"otf", @"woff", @"woff2"],
               12, iterationsPerSeed, stopFlag, logBlock, hits, sem1);

    // AudioToolbox — audio files, preserve first 12 bytes (RIFF/MPEG/AIFF magic + size)
    runSurface(FuzzSurfaceAudioToolbox, @"AudioTB",
               tryAudioFile,
               @[@"mp3", @"m4a", @"aiff", @"wav", @"caf"],
               12, iterationsPerSeed, stopFlag, logBlock, hits, sem2);

    // NSKeyedUnarchiver — NSArchiver plists, preserve first 8 bytes (bplist00 magic)
    runSurface(FuzzSurfaceUnarchiver, @"Unarchive",
               tryUnarchiver,
               @[@"plist", @"nsa"],
               8, iterationsPerSeed, stopFlag, logBlock, hits, sem3);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        dispatch_semaphore_wait(sem1, DISPATCH_TIME_FOREVER);
        dispatch_semaphore_wait(sem2, DISPATCH_TIME_FOREVER);
        dispatch_semaphore_wait(sem3, DISPATCH_TIME_FOREVER);
        dispatch_async(dispatch_get_main_queue(), ^{ completion(hits); });
    });
}
