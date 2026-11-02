// Sources/PDFFuzz.m
// lang: ObjC, file: PDFFuzz.m, target: iOS 15+
#import "CorpusData.h"
// PDF parser fuzzer — three independent attack surfaces.
//
// CGPDFDocument path:
//   CGDataProviderCreateWithCFData → CGPDFDocumentCreateWithProvider
//   Enumerate pages → CGPDFPageGetDictionary → walk /Resources /Font dict
//   Pull stream data from /Contents entries
//   Integer overflow targets: page count, xref offsets, stream length fields.
//
// PDFKit path:
//   -[PDFDocument initWithData:] (ObjC) — different parser branch from CGPDF.
//   Enumerate pages via PDFPage, read annotations (PDFAnnotation), outlines.
//   Form fields: -[PDFDocument findString:withOptions:] triggers search index.
//
// Embedded font path:
//   Walks CGPDFDocument /Resources /Font for each page.
//   For any font with /FontFile, /FontFile2, /FontFile3 — extract raw stream bytes.
//   Feed directly to CTFontManagerCreateFontDescriptorsFromData.
//   This is the chollima delivery vector: PDF → CoreText font parser.
//
// Mutation strategy: header-preserving (first 8 bytes = PDF magic "%PDF-1."),
// then aggressive field smashing on the rest.  PDF is text-based in the header
// so preserving "%PDF-1." keeps the parser on the right code path long enough
// to hit deep state before the corruption lands.
//
// Corpus seeds: see tools/gen_corpus.py (pdf section).

#import "PDFFuzz.h"
#import "ExceptionCatcher.h"
#import <CoreText/CoreText.h>
#import <PDFKit/PDFKit.h>
#import <CoreGraphics/CoreGraphics.h>

// ── mutation engine (shared with SurfaceFuzz style) ──────────────────────────

static NSData *pdfMutate(NSData *seed, NSUInteger iter, NSUInteger headerBytes) {
    NSMutableData *m = [seed mutableCopy];
    uint8_t *bytes   = (uint8_t *)m.mutableBytes;
    NSUInteger len   = m.length;
    if (len <= headerBytes) headerBytes = 0;

    uint64_t rng = (uint64_t)iter ^ ((uint64_t)len << 32) ^ 0xC0FFEEBADF00D;
    #define PRAND() ({ rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; rng; })

    NSUInteger ops = 1 + (NSUInteger)(PRAND() % 10);
    for (NSUInteger i = 0; i < ops; i++) {
        NSUInteger range = len - headerBytes;
        if (range == 0) break;
        NSUInteger pos = headerBytes + (NSUInteger)(PRAND() % range);

        int op = (int)(PRAND() % 9);
        switch (op) {
            case 0: bytes[pos] ^= (uint8_t)(PRAND() & 0xFF); break;
            case 1: { uint8_t b[] = {0,1,0x7F,0x80,0xFE,0xFF}; bytes[pos] = b[PRAND()%6]; break; }
            case 2: { NSUInteger e = MIN(pos+32, len); memset(bytes+pos, 0, e-pos); break; }
            case 3: { NSUInteger e = MIN(pos+32, len); memset(bytes+pos, 0xFF, e-pos); break; }
            // Smash a 4-byte big-endian integer field — prime for xref offset overflow
            case 4: if (pos+4 <= len) { bytes[pos]=0xFF; bytes[pos+1]=0xFF; bytes[pos+2]=0xFF; bytes[pos+3]=0xFF; } break;
            case 5: if (pos+4 <= len) { bytes[pos]=0; bytes[pos+1]=0; bytes[pos+2]=0; bytes[pos+3]=0; } break;
            // Corrupt /Length field — stream over-read / buffer overflow
            case 6: { // find next "Length" and overwrite its value
                const char *needle = "/Length";
                const uint8_t *base = (const uint8_t *)m.bytes;
                NSUInteger search = pos;
                while (search + 7 < len) {
                    if (memcmp(base + search, needle, 7) == 0) {
                        // skip whitespace and digits after /Length, write large number
                        NSUInteger wp = search + 7;
                        while (wp < len && (base[wp] == ' ' || base[wp] == '\n' || base[wp] == '\r')) wp++;
                        if (wp + 8 < len) {
                            // write "99999999"
                            memcpy(bytes + wp, "99999999", 8);
                        }
                        break;
                    }
                    search++;
                }
                break;
            }
            // Truncate into xref section
            case 7: m.length = MAX(headerBytes + 4, pos); bytes = (uint8_t *)m.mutableBytes; len = m.length; break;
            // Flip sign bit of a /Count or /Index value — page count integer issues
            case 8: {
                const char *cneedle = "/Count ";
                const uint8_t *base = (const uint8_t *)m.bytes;
                NSUInteger search = pos;
                while (search + 7 < len) {
                    if (memcmp(base + search, cneedle, 7) == 0) {
                        NSUInteger wp = search + 7;
                        if (wp + 10 < len) { memcpy(bytes + wp, "2147483648", 10); }
                        break;
                    }
                    search++;
                }
                break;
            }
        }
    }
    #undef PRAND
    return m;
}

// C callback for CGPDFDictionaryApplyFunction — touches each value to trigger lazy parsing.
static void touchFontEntry(const char *key, CGPDFObjectRef obj, void *info) {
    (void)CGPDFObjectGetType(obj);
}

// ── CGPDFDocument surface ─────────────────────────────────────────────────────

static void walkCGPDFDict(CGPDFDictionaryRef dict, void (^visitor)(CGPDFStreamRef));

static void cgpdfStreamVisitor(const char *key, CGPDFObjectRef obj, void *ctx) {
    void (^visitor)(CGPDFStreamRef) = (__bridge void(^)(CGPDFStreamRef))ctx;
    CGPDFObjectType type = CGPDFObjectGetType(obj);
    if (type == kCGPDFObjectTypeStream) {
        CGPDFStreamRef stream = NULL;
        if (CGPDFObjectGetValue(obj, kCGPDFObjectTypeStream, &stream) && stream) {
            visitor(stream);
        }
    } else if (type == kCGPDFObjectTypeDictionary) {
        CGPDFDictionaryRef sub = NULL;
        if (CGPDFObjectGetValue(obj, kCGPDFObjectTypeDictionary, &sub) && sub) {
            walkCGPDFDict(sub, visitor);
        }
    }
}

static void walkCGPDFDict(CGPDFDictionaryRef dict, void (^visitor)(CGPDFStreamRef)) {
    CGPDFDictionaryApplyFunction(dict, cgpdfStreamVisitor, (__bridge void *)visitor);
}

static BOOL tryCGPDF(NSData *data, NSString **outDesc) {
    __block BOOL hit = NO;
    __block NSString *desc = nil;

    NSError *err = [ObjCExceptionCatcher runCatching:^{
        CFDataRef cfdata = (__bridge CFDataRef)data;
        CGDataProviderRef prov = CGDataProviderCreateWithCFData(cfdata);
        if (!prov) return;
        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(prov);
        CGDataProviderRelease(prov);
        if (!doc) return;

        size_t pageCount = CGPDFDocumentGetNumberOfPages(doc);
        // Cap at 5 pages to avoid spending forever on a giant-page-count bomb.
        size_t pagesToScan = MIN(pageCount, 5);

        for (size_t p = 1; p <= pagesToScan; p++) {
            CGPDFPageRef page = CGPDFDocumentGetPage(doc, p);
            if (!page) continue;

            CGPDFDictionaryRef pageDict = CGPDFPageGetDictionary(page);
            if (!pageDict) continue;

            // Walk all streams on the page (hits /Contents, inline images, etc.)
            walkCGPDFDict(pageDict, ^(CGPDFStreamRef stream) {
                CGPDFDataFormat fmt;
                CFDataRef sd = CGPDFStreamCopyData(stream, &fmt);
                if (sd) CFRelease(sd);
            });

            // Try to access /Resources /Font — embedded font vector
            CGPDFDictionaryRef resources = NULL;
            if (CGPDFDictionaryGetDictionary(pageDict, "Resources", &resources) && resources) {
                CGPDFDictionaryRef fontDict = NULL;
                if (CGPDFDictionaryGetDictionary(resources, "Font", &fontDict) && fontDict) {
                    // Force iteration — exercises font descriptor lazy parsing.
                    CGPDFDictionaryApplyFunction(fontDict, touchFontEntry, NULL);
                }
            }
        }

        CGPDFDocumentRelease(doc);
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

// ── PDFKit surface ────────────────────────────────────────────────────────────

static BOOL tryPDFKit(NSData *data, NSString **outDesc) {
    __block BOOL hit = NO;
    __block NSString *desc = nil;

    NSError *err = [ObjCExceptionCatcher runCatching:^{
        PDFDocument *doc = [[PDFDocument alloc] initWithData:data];
        if (!doc) return;

        NSInteger pageCount = doc.pageCount;
        NSInteger pagesToScan = MIN(pageCount, 5);

        for (NSInteger p = 0; p < pagesToScan; p++) {
            PDFPage *page = [doc pageAtIndex:p];
            if (!page) continue;

            // Force text extraction — exercises font rendering + glyph lookup
            (void)[page string];

            // Walk annotations — hits annotation parser, action dict decoder
            for (PDFAnnotation *ann in page.annotations) {
                (void)ann.type;
                (void)ann.bounds;
                if (ann.action) (void)ann.action.description;
            }
        }

        // Outline traversal — exercises outline dict parser, named destination resolver
        PDFOutline *outline = doc.outlineRoot;
        if (outline) {
            for (NSInteger i = 0; i < MIN(outline.numberOfChildren, 20); i++) {
                PDFOutline *child = [outline childAtIndex:i];
                (void)child.label;
                (void)child.destination;
            }
        }

        // Search triggers the internal search index build — hits font metric lookups
        // Use a short unique string that won't actually match, just to exercise the path
        (void)[doc findString:@"\x01\x02\x03" withOptions:0];
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

// ── Embedded font surface — the chollima vector ───────────────────────────────
// Extracts /FontFile* streams from each page's /Resources /Font dict and
// feeds the raw bytes into CTFontManagerCreateFontDescriptorsFromData.
// This is the exact chain that chollima triggers via a malicious PDF attachment.

typedef struct {
    NSMutableArray<NSData *> *fonts;
} EmbeddedFontCtx;

static void collectFontDescriptors(const char *key, CGPDFObjectRef obj, void *ctx) {
    EmbeddedFontCtx *c = (EmbeddedFontCtx *)ctx;

    CGPDFDictionaryRef fontRef = NULL;
    if (!CGPDFObjectGetValue(obj, kCGPDFObjectTypeDictionary, &fontRef) || !fontRef) return;

    // Navigate to /FontDescriptor
    CGPDFDictionaryRef fdesc = NULL;
    if (!CGPDFDictionaryGetDictionary(fontRef, "FontDescriptor", &fdesc) || !fdesc) return;

    // Try all three font file stream keys
    const char *fontFileKeys[] = { "FontFile", "FontFile2", "FontFile3" };
    for (int k = 0; k < 3; k++) {
        CGPDFStreamRef stream = NULL;
        if (CGPDFDictionaryGetStream(fdesc, fontFileKeys[k], &stream) && stream) {
            CGPDFDataFormat fmt;
            CFDataRef sd = CGPDFStreamCopyData(stream, &fmt);
            if (sd) {
                [c->fonts addObject:(__bridge NSData *)sd];
                CFRelease(sd);
            }
        }
    }
}

static BOOL tryEmbeddedFonts(NSData *data, NSString **outDesc) {
    __block BOOL hit = NO;
    __block NSString *desc = nil;

    NSError *err = [ObjCExceptionCatcher runCatching:^{
        CFDataRef cfdata  = (__bridge CFDataRef)data;
        CGDataProviderRef prov = CGDataProviderCreateWithCFData(cfdata);
        if (!prov) return;
        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(prov);
        CGDataProviderRelease(prov);
        if (!doc) return;

        EmbeddedFontCtx ctx = { .fonts = [NSMutableArray array] };

        size_t pageCount = MIN(CGPDFDocumentGetNumberOfPages(doc), 5);
        for (size_t p = 1; p <= pageCount; p++) {
            CGPDFPageRef page = CGPDFDocumentGetPage(doc, p);
            if (!page) continue;
            CGPDFDictionaryRef pageDict = CGPDFPageGetDictionary(page);
            if (!pageDict) continue;
            CGPDFDictionaryRef resources = NULL;
            if (!CGPDFDictionaryGetDictionary(pageDict, "Resources", &resources) || !resources) continue;
            CGPDFDictionaryRef fontDict = NULL;
            if (!CGPDFDictionaryGetDictionary(resources, "Font", &fontDict) || !fontDict) continue;
            CGPDFDictionaryApplyFunction(fontDict, collectFontDescriptors, &ctx);
        }

        CGPDFDocumentRelease(doc);

        // Now run each extracted font through CoreText — the chollima vector
        for (NSData *fontData in ctx.fonts) {
            CFDataRef cfFont = (__bridge CFDataRef)fontData;
            CFArrayRef descs = CTFontManagerCreateFontDescriptorsFromData(cfFont);
            if (descs) {
                CFIndex count = CFArrayGetCount(descs);
                for (CFIndex i = 0; i < count; i++) {
                    CTFontDescriptorRef fd = (CTFontDescriptorRef)CFArrayGetValueAtIndex(descs, i);
                    CTFontRef font = CTFontCreateWithFontDescriptor(fd, 12.0f, NULL);
                    if (font) {
                        // Force glyph metric resolve — hits CFF charstring / TT glyf
                        CGGlyph glyphs[256]; UniChar chars[256];
                        for (int j = 0; j < 256; j++) chars[j] = (UniChar)j;
                        CTFontGetGlyphsForCharacters(font, chars, glyphs, 256);
                        CGRect rects[256];
                        CTFontGetBoundingRectsForGlyphs(font, kCTFontOrientationDefault, glyphs, rects, 256);
                        CFRelease(font);
                    }
                }
                CFRelease(descs);
            }
        }
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

// ── per-surface run loop (mirrors SurfaceFuzz.m) ─────────────────────────────

typedef BOOL (*PDFTryFn)(NSData *, NSString **);

static void runPDFSurface(PDFFuzzSubsurface subsurface,
                          NSString *label,
                          PDFTryFn tryFn,
                          NSUInteger iters,
                          volatile BOOL *stopFlag,
                          void (^logBlock)(NSString *),
                          NSMutableArray<PDFFuzzResult *> *hits,
                          dispatch_semaphore_t done) {

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        // Embedded PDF corpus seeds — no bundle lookup.
        struct { const uint8_t *ptr; NSUInteger len; NSString *name; } table[] = { CORPUS_PDF_SEEDS };
        NSMutableArray<NSDictionary *> *seeds = [NSMutableArray array];
        for (NSUInteger i = 0; i < sizeof(table)/sizeof(table[0]); i++) {
            [seeds addObject:@{@"name": table[i].name,
                               @"data": [NSData dataWithBytes:table[i].ptr length:table[i].len]}];
        }

        logBlock([NSString stringWithFormat:@"%@: %lu seeds × %lu iter",
            label, (unsigned long)seeds.count, (unsigned long)iters]);

        if (seeds.count == 0) {
            logBlock([NSString stringWithFormat:@"%@: WARNING no seeds found", label]);
            dispatch_semaphore_signal(done);
            return;
        }

        NSUInteger hitCount = 0;
        for (NSDictionary *seed in seeds) {
            if (stopFlag && *stopFlag) break;
            NSString *name = seed[@"name"];
            NSData   *data = seed[@"data"];

            for (NSUInteger iter = 0; iter < iters; iter++) {
                if (stopFlag && *stopFlag) break;
                // Preserve first 8 bytes — "%PDF-1.X" magic keeps the parser on the hot path
                NSData *mutant = pdfMutate(data, iter, 8);
                NSString *desc = nil;
                BOOL hit = tryFn(mutant, &desc);

                if (hit) {
                    hitCount++;
                    PDFFuzzResult *r = [[PDFFuzzResult alloc] init];
                    r.subsurface = subsurface;
                    r.seedName   = name;
                    r.iteration  = iter;
                    r.crashed    = (desc && [desc hasPrefix:@"EXCEPTION"]);
                    r.desc       = desc;
                    r.reproducer = mutant;
                    @synchronized(hits) { [hits addObject:r]; }

                    logBlock([NSString stringWithFormat:
                        @"%@: HIT seed=%@ iter=%lu: %@",
                        label, name, (unsigned long)iter, desc]);

                    NSString *docs = [NSSearchPathForDirectoriesInDomains(
                        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
                    NSString *repName = [NSString stringWithFormat:
                        @"repr_%@_%@_iter%lu.pdf", label,
                        [name stringByDeletingPathExtension], (unsigned long)iter];
                    [mutant writeToFile:[docs stringByAppendingPathComponent:repName] atomically:YES];
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

@implementation PDFFuzzResult @end

void PDFFuzzRun(NSUInteger iterationsPerSeed,
                volatile BOOL *stopFlag,
                void (^logBlock)(NSString *line),
                void (^completion)(NSArray<PDFFuzzResult *> *hits)) {

    NSMutableArray<PDFFuzzResult *> *hits = [NSMutableArray array];

    dispatch_semaphore_t sem1 = dispatch_semaphore_create(0);
    dispatch_semaphore_t sem2 = dispatch_semaphore_create(0);
    dispatch_semaphore_t sem3 = dispatch_semaphore_create(0);

    // CGPDFDocument — raw parser
    runPDFSurface(PDFFuzzSubsurfaceCGPDF, @"CGPDF",
                  tryCGPDF, iterationsPerSeed, stopFlag, logBlock, hits, sem1);

    // PDFKit — ObjC parser + annotation/outline paths
    runPDFSurface(PDFFuzzSubsurfacePDFKit, @"PDFKit",
                  tryPDFKit, iterationsPerSeed, stopFlag, logBlock, hits, sem2);

    // Embedded font path — the chollima vector: PDF → CoreText
    runPDFSurface(PDFFuzzSubsurfaceEmbeddedFont, @"EmbFont",
                  tryEmbeddedFonts, iterationsPerSeed, stopFlag, logBlock, hits, sem3);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        dispatch_semaphore_wait(sem1, DISPATCH_TIME_FOREVER);
        dispatch_semaphore_wait(sem2, DISPATCH_TIME_FOREVER);
        dispatch_semaphore_wait(sem3, DISPATCH_TIME_FOREVER);
        dispatch_async(dispatch_get_main_queue(), ^{ completion(hits); });
    });
}
