// CorpusData.h — embedded corpus seeds, auto-generated
// Do not edit by hand.
#pragma once
#import <Foundation/Foundation.h>

// ── image ─────────────────────────────────
extern const uint8_t kSeed_valid_1x1_png[];
extern const NSUInteger kSeed_valid_1x1_png_len;
extern const uint8_t kSeed_bad_crc_png[];
extern const NSUInteger kSeed_bad_crc_png_len;
extern const uint8_t kSeed_truncated_png[];
extern const NSUInteger kSeed_truncated_png_len;
extern const uint8_t kSeed_zero_idat_png[];
extern const NSUInteger kSeed_zero_idat_png_len;
extern const uint8_t kSeed_valid_1x1_jpg[];
extern const NSUInteger kSeed_valid_1x1_jpg_len;
extern const uint8_t kSeed_bad_marker_jpg[];
extern const NSUInteger kSeed_bad_marker_jpg_len;
extern const uint8_t kSeed_truncated_jpg[];
extern const NSUInteger kSeed_truncated_jpg_len;
extern const uint8_t kSeed_valid_gif[];
extern const NSUInteger kSeed_valid_gif_len;
extern const uint8_t kSeed_bad_magic_gif[];
extern const NSUInteger kSeed_bad_magic_gif_len;
extern const uint8_t kSeed_truncated_gif[];
extern const NSUInteger kSeed_truncated_gif_len;
extern const uint8_t kSeed_bad_ftyp_heic[];
extern const NSUInteger kSeed_bad_ftyp_heic_len;
extern const uint8_t kSeed_truncated_heic[];
extern const NSUInteger kSeed_truncated_heic_len;
extern const uint8_t kSeed_valid_webp[];
extern const NSUInteger kSeed_valid_webp_len;
extern const uint8_t kSeed_bad_magic_webp[];
extern const NSUInteger kSeed_bad_magic_webp_len;
extern const uint8_t kSeed_truncated_webp[];
extern const NSUInteger kSeed_truncated_webp_len;

#define CORPUS_IMAGE_SEEDS \
    {(const uint8_t *)kSeed_valid_1x1_png, kSeed_valid_1x1_png_len, @"valid_1x1.png"},\
    {(const uint8_t *)kSeed_bad_crc_png, kSeed_bad_crc_png_len, @"bad_crc.png"},\
    {(const uint8_t *)kSeed_truncated_png, kSeed_truncated_png_len, @"truncated.png"},\
    {(const uint8_t *)kSeed_zero_idat_png, kSeed_zero_idat_png_len, @"zero_idat.png"},\
    {(const uint8_t *)kSeed_valid_1x1_jpg, kSeed_valid_1x1_jpg_len, @"valid_1x1.jpg"},\
    {(const uint8_t *)kSeed_bad_marker_jpg, kSeed_bad_marker_jpg_len, @"bad_marker.jpg"},\
    {(const uint8_t *)kSeed_truncated_jpg, kSeed_truncated_jpg_len, @"truncated.jpg"},\
    {(const uint8_t *)kSeed_valid_gif, kSeed_valid_gif_len, @"valid.gif"},\
    {(const uint8_t *)kSeed_bad_magic_gif, kSeed_bad_magic_gif_len, @"bad_magic.gif"},\
    {(const uint8_t *)kSeed_truncated_gif, kSeed_truncated_gif_len, @"truncated.gif"},\
    {(const uint8_t *)kSeed_bad_ftyp_heic, kSeed_bad_ftyp_heic_len, @"bad_ftyp.heic"},\
    {(const uint8_t *)kSeed_truncated_heic, kSeed_truncated_heic_len, @"truncated.heic"},\
    {(const uint8_t *)kSeed_valid_webp, kSeed_valid_webp_len, @"valid.webp"},\
    {(const uint8_t *)kSeed_bad_magic_webp, kSeed_bad_magic_webp_len, @"bad_magic.webp"},\
    {(const uint8_t *)kSeed_truncated_webp, kSeed_truncated_webp_len, @"truncated.webp"}

// ── surface ─────────────────────────────────
extern const uint8_t kSeed_valid_ttf[];
extern const NSUInteger kSeed_valid_ttf_len;
extern const uint8_t kSeed_bad_numtables_ttf[];
extern const NSUInteger kSeed_bad_numtables_ttf_len;
extern const uint8_t kSeed_truncated_ttf[];
extern const NSUInteger kSeed_truncated_ttf_len;
extern const uint8_t kSeed_valid_wav[];
extern const NSUInteger kSeed_valid_wav_len;
extern const uint8_t kSeed_bad_size_wav[];
extern const NSUInteger kSeed_bad_size_wav_len;
extern const uint8_t kSeed_truncated_wav[];
extern const NSUInteger kSeed_truncated_wav_len;
extern const uint8_t kSeed_valid_archive_plist[];
extern const NSUInteger kSeed_valid_archive_plist_len;
extern const uint8_t kSeed_bad_version_plist[];
extern const NSUInteger kSeed_bad_version_plist_len;
extern const uint8_t kSeed_deep_archive_plist[];
extern const NSUInteger kSeed_deep_archive_plist_len;
extern const uint8_t kSeed_valid_aiff[];
extern const NSUInteger kSeed_valid_aiff_len;
extern const uint8_t kSeed_overflow_frames_aiff[];
extern const NSUInteger kSeed_overflow_frames_aiff_len;

extern const uint8_t kSeed_real_caf[];
extern const NSUInteger kSeed_real_caf_len;
#define CORPUS_SURFACE_SEEDS \
    {(const uint8_t *)kSeed_valid_ttf, kSeed_valid_ttf_len, @"valid.ttf"},\
    {(const uint8_t *)kSeed_bad_numtables_ttf, kSeed_bad_numtables_ttf_len, @"bad_numtables.ttf"},\
    {(const uint8_t *)kSeed_truncated_ttf, kSeed_truncated_ttf_len, @"truncated.ttf"},\
    {(const uint8_t *)kSeed_valid_wav, kSeed_valid_wav_len, @"valid.wav"},\
    {(const uint8_t *)kSeed_bad_size_wav, kSeed_bad_size_wav_len, @"bad_size.wav"},\
    {(const uint8_t *)kSeed_truncated_wav, kSeed_truncated_wav_len, @"truncated.wav"},\
    {(const uint8_t *)kSeed_valid_archive_plist, kSeed_valid_archive_plist_len, @"valid_archive.plist"},\
    {(const uint8_t *)kSeed_bad_version_plist, kSeed_bad_version_plist_len, @"bad_version.plist"},\
    {(const uint8_t *)kSeed_deep_archive_plist, kSeed_deep_archive_plist_len, @"deep_archive.plist"},\
    {(const uint8_t *)kSeed_valid_aiff, kSeed_valid_aiff_len, @"valid.aiff"},\
    {(const uint8_t *)kSeed_overflow_frames_aiff, kSeed_overflow_frames_aiff_len, @"overflow_frames.aiff"},\
    {(const uint8_t *)kSeed_real_caf, kSeed_real_caf_len, @"real.caf"}

// ── pdf ─────────────────────────────────
extern const uint8_t kSeed_seed_minimal_pdf[];
extern const NSUInteger kSeed_seed_minimal_pdf_len;
extern const uint8_t kSeed_seed_embedded_ttf_pdf[];
extern const NSUInteger kSeed_seed_embedded_ttf_pdf_len;
extern const uint8_t kSeed_seed_malformed_xref_pdf[];
extern const NSUInteger kSeed_seed_malformed_xref_pdf_len;
extern const uint8_t kSeed_seed_truncated_stream_pdf[];
extern const NSUInteger kSeed_seed_truncated_stream_pdf_len;
extern const uint8_t kSeed_seed_giant_pagecount_pdf[];
extern const NSUInteger kSeed_seed_giant_pagecount_pdf_len;
extern const uint8_t kSeed_seed_bad_filter_pdf[];
extern const NSUInteger kSeed_seed_bad_filter_pdf_len;

#define CORPUS_PDF_SEEDS \
    {(const uint8_t *)kSeed_seed_minimal_pdf, kSeed_seed_minimal_pdf_len, @"seed_minimal.pdf"},\
    {(const uint8_t *)kSeed_seed_embedded_ttf_pdf, kSeed_seed_embedded_ttf_pdf_len, @"seed_embedded_ttf.pdf"},\
    {(const uint8_t *)kSeed_seed_malformed_xref_pdf, kSeed_seed_malformed_xref_pdf_len, @"seed_malformed_xref.pdf"},\
    {(const uint8_t *)kSeed_seed_truncated_stream_pdf, kSeed_seed_truncated_stream_pdf_len, @"seed_truncated_stream.pdf"},\
    {(const uint8_t *)kSeed_seed_giant_pagecount_pdf, kSeed_seed_giant_pagecount_pdf_len, @"seed_giant_pagecount.pdf"},\
    {(const uint8_t *)kSeed_seed_bad_filter_pdf, kSeed_seed_bad_filter_pdf_len, @"seed_bad_filter.pdf"}

