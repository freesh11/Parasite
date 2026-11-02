#!/usr/bin/env python3
"""
tools/gen_corpus.py  v3
Generate seed corpus for v13 multi-surface fuzzer.

Formats produced:
  Image:  PNG, JPEG, WebP, GIF, HEIC
  Font:   TTF, OTF, WOFF, WOFF2
  Audio:  WAV, AIFF, MP3, CAF, M4A (AAC-in-MP4)
  Other:  plist (NSKeyedArchiver)
  PDF:    minimal, embedded-TTF, malformed-xref, truncated-stream,
          giant-pagecount, bad-filter

PDF notes:
  seed_minimal.pdf          — valid 1-page PDF, no fonts; baseline parser path
  seed_embedded_ttf.pdf     — /FontFile2 stream with TTF magic; chollima-mimic seed
                              hits PDF → CoreText chain (the delivery vector)
  seed_malformed_xref.pdf   — startxref points to garbage offset; xref recovery
  seed_truncated_stream.pdf — /Length lies; stream over-read target
  seed_giant_pagecount.pdf  — /Count 2147483647; integer overflow in page tree
  seed_bad_filter.pdf       — unknown /Filter value; filter dispatch table

All seeds are minimal valid-format bytestreams hand-crafted to survive
header recognition and reach deep parser state.
"""
import os, struct, zlib, io
from pathlib import Path

try:
    from PIL import Image
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

CORPUS = Path(__file__).parent.parent / "corpus"
CORPUS.mkdir(exist_ok=True)

# ── helpers ───────────────────────────────────────────────────────────────────

def u16be(n): return struct.pack(">H", n & 0xFFFF)
def u32be(n): return struct.pack(">I", n & 0xFFFFFFFF)
def u16le(n): return struct.pack("<H", n & 0xFFFF)
def u32le(n): return struct.pack("<I", n & 0xFFFFFFFF)

# ── image seeds (unchanged from v11) ─────────────────────────────────────────

def _png_chunk(tag, data):
    ln = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return ln + tag + data + crc

def make_png_raw(w, h, colortype=2, bitdepth=8):
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr = struct.pack(">IIBBBBB", w, h, bitdepth, colortype, 0, 0, 0)
    idat_raw = b''
    for _ in range(h):
        idat_raw += b'\x00' + b'\x80\x40\x20' * w
    idat = _png_chunk(b'IDAT', zlib.compress(idat_raw))
    return sig + _png_chunk(b'IHDR', ihdr) + idat + _png_chunk(b'IEND', b'')

def write_image_seeds():
    seeds = {}
    # PNG
    seeds["valid_rgb.png"]   = make_png_raw(16, 16, colortype=2)
    seeds["valid_rgba.png"]  = make_png_raw(4,  4,  colortype=6)
    seeds["valid_1x1.png"]   = make_png_raw(1,  1,  colortype=2)
    seeds["zero_idat.png"]   = (
        b'\x89PNG\r\n\x1a\n'
        + _png_chunk(b'IHDR', struct.pack(">IIBBBBB", 4,4,8,2,0,0,0))
        + _png_chunk(b'IDAT', zlib.compress(b'\x00'*13*4))
        + _png_chunk(b'IEND', b''))
    ba = bytearray(seeds["valid_rgb.png"]); ba[20] ^= 0xFF
    seeds["bad_crc.png"]      = bytes(ba)
    seeds["truncated.png"]    = seeds["valid_rgb.png"][:40]

    # JPEG
    if HAS_PILLOW:
        for spec in [(16,16,"RGB"),(1,1,"L"),(64,1,"RGB")]:
            img = Image.new(spec[2], (spec[0], spec[1]), 128)
            buf = io.BytesIO(); img.save(buf, "JPEG", quality=75)
            seeds[f"valid_{spec[0]}x{spec[1]}.jpg"] = buf.getvalue()
    else:
        # minimal JFIF stub
        jfif = (b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
                b'\xFF\xD9')
        seeds["valid.jpg"] = jfif
    raw = list(seeds.values())[-1]
    seeds["truncated.jpg"] = raw[:len(raw)//2]

    # WebP
    if HAS_PILLOW:
        img = Image.new("RGB", (8, 8), (100,150,200))
        buf = io.BytesIO(); img.save(buf, "WEBP", quality=75)
        seeds["valid.webp"] = buf.getvalue()
    else:
        vp8 = bytes([0x30,0x01,0x00,0x9d,0x01,0x2a,0x01,0x00,0x01,0x00,
                     0x00,0x34,0x25,0x9f,0x04,0x00,0xfe,0xef,0x8a])
        chunk = b'VP8 ' + struct.pack("<I", len(vp8)) + vp8
        seeds["valid.webp"] = b'RIFF' + struct.pack("<I", 4+len(chunk)) + b'WEBP' + chunk
    raw = seeds["valid.webp"]
    ba = bytearray(raw); ba[8] ^= 0xFF
    seeds["bad_magic.webp"] = bytes(ba)

    # GIF
    if HAS_PILLOW:
        img = Image.new("P", (4,4)); img.putpalette([i for i in range(192)]+[0]*63)
        buf = io.BytesIO(); img.save(buf, "GIF")
        seeds["valid.gif"] = buf.getvalue()
    else:
        seeds["valid.gif"] = (b'GIF89a\x04\x00\x04\x00\x80\x00\x00\xFF\x00\x00\x00\xFF\x00'
                               b'\x2C\x00\x00\x00\x00\x04\x00\x04\x00\x00\x02\x01\x00\x00\x3B')
    # HEIC minimal ftyp
    def box(fc, p): s=8+len(p); return struct.pack(">I",s)+fc+p
    ftyp = box(b'ftyp', b'heic'+u32be(0)+b'heicmif1iso8')
    seeds["valid_container.heic"] = ftyp + box(b'mdat', b'')
    seeds["truncated.heic"]       = seeds["valid_container.heic"][:8]

    for name, data in seeds.items():
        (CORPUS / name).write_bytes(data)
    print(f"  wrote {len(seeds)} image seeds")

# ── font seeds ────────────────────────────────────────────────────────────────
# Minimal TTF/OTF using sfnt container. CoreText will parse the table directory
# and attempt to load glyph metrics even on malformed tables.

def make_ttf_minimal():
    """
    Minimal TTF: sfnt header + empty table for 'cmap','glyf','head','hhea',
    'hmtx','loca','maxp','name','post'. Just enough for CoreText to reach
    glyph-metric code paths.
    """
    # sfnt offset table: version=0x00010000 (TrueType), numTables, searchRange, etc.
    tables = [b'cmap', b'glyf', b'head', b'hhea', b'hmtx', b'loca', b'maxp', b'name', b'post']
    n = len(tables)
    entry_size = 16
    header_size = 12 + n * entry_size
    # Each table: 4 bytes of data (minimum non-empty)
    table_data = b'\x00\x00\x00\x01' * n

    def calc_checksum(data):
        # pad to 4-byte boundary
        while len(data) % 4: data += b'\x00'
        s = 0
        for i in range(0, len(data), 4):
            s = (s + struct.unpack(">I", data[i:i+4])[0]) & 0xFFFFFFFF
        return s

    out = b''
    # sfnt offset table
    pow2 = 1
    while pow2 * 2 <= n: pow2 *= 2
    search_range = pow2 * 16
    entry_selector = pow2.bit_length() - 1
    range_shift = n * 16 - search_range
    out += u32be(0x00010000) + u16be(n) + u16be(search_range) + u16be(entry_selector) + u16be(range_shift)

    # Table records (offset = header_size + i*4)
    for i, tag in enumerate(tables):
        offset = header_size + i * 4
        data_slice = table_data[i*4:(i+1)*4]
        checksum = calc_checksum(data_slice)
        out += tag + u32be(checksum) + u32be(offset) + u32be(4)

    out += table_data
    return out

def make_otf_minimal():
    """CFF-flavoured OpenType: version=0x4F54544F ('OTTO')."""
    data = make_ttf_minimal()
    # Patch version to OTTO
    return b'OTTO' + data[4:]

def make_woff_minimal(sfnt_data):
    """WOFF container wrapping the sfnt data."""
    # WOFF header
    signature   = b'wOFF'
    flavor      = u32be(0x00010000)
    length      = u32be(44 + len(sfnt_data))  # header + no table directory + data
    num_tables  = u16be(0)
    reserved    = u16be(0)
    total_sfnt  = u32be(len(sfnt_data))
    major       = u16be(1)
    minor       = u16be(0)
    meta_offset = u32be(0)
    meta_length = u32be(0)
    meta_orig   = u32be(0)
    priv_offset = u32be(0)
    priv_length = u32be(0)
    return (signature + flavor + length + num_tables + reserved +
            total_sfnt + major + minor + meta_offset + meta_length +
            meta_orig + priv_offset + priv_length + sfnt_data)

def write_font_seeds():
    ttf  = make_ttf_minimal()
    otf  = make_otf_minimal()
    woff = make_woff_minimal(ttf)
    seeds = {
        "valid.ttf":        ttf,
        "valid.otf":        otf,
        "valid.woff":       woff,
        # Corrupt the table count field — integer overflow target
        "bad_numtables.ttf": bytes([ttf[0],ttf[1],ttf[2],ttf[3],0xFF,0xFF]) + ttf[6:],
        # Truncated mid-table-directory
        "truncated.ttf":    ttf[:20],
        "truncated.otf":    otf[:20],
    }
    for name, data in seeds.items():
        (CORPUS / name).write_bytes(data)
    print(f"  wrote {len(seeds)} font seeds")

# ── audio seeds ───────────────────────────────────────────────────────────────

def make_wav_minimal(num_samples=8, sample_rate=44100, channels=1, bits=16):
    """Minimal PCM WAV."""
    data_size = num_samples * channels * (bits // 8)
    pcm_data  = bytes(data_size)
    fmt_chunk  = (u16le(1)                  # PCM
                + u16le(channels)
                + u32le(sample_rate)
                + u32le(sample_rate * channels * bits // 8)
                + u16le(channels * bits // 8)
                + u16le(bits))
    riff_size  = 4 + (8 + len(fmt_chunk)) + (8 + len(pcm_data))
    return (b'RIFF' + u32le(riff_size) + b'WAVE'
            + b'fmt ' + u32le(len(fmt_chunk)) + fmt_chunk
            + b'data' + u32le(len(pcm_data)) + pcm_data)

def make_aiff_minimal():
    """Minimal AIFF (big-endian PCM)."""
    # COMM chunk: 1 ch, 8 sampleFrames, 16 bit, 44100 Hz (80-bit extended)
    # 44100 as 80-bit IEEE 754 extended: 0x400E AC44 0000 0000 0000
    comm = (u16be(1)                        # channels
           + u32be(8)                       # sampleFrames
           + u16be(16)                      # sampleSize
           + bytes([0x40,0x0E,0xAC,0x44,0x00,0x00,0x00,0x00,0x00,0x00]))  # 44100 Hz
    ssnd = u32be(0) + u32be(0) + bytes(16)  # offset + blockSize + 8 sample frames * 2 bytes
    form_size = 4 + (8+len(comm)) + (8+len(ssnd))
    return (b'FORM' + u32be(form_size) + b'AIFF'
            + b'COMM' + u32be(len(comm)) + comm
            + b'SSND' + u32be(len(ssnd)) + ssnd)

def make_mp3_minimal():
    """
    Minimal MP3 frame: MPEG-1 Layer 3, 128kbps, 44100Hz, stereo.
    Frame header bytes: 0xFF 0xFB 0x90 0x00
    Frame size = 144 * bitrate / samplerate + padding = 144*128000/44100 = 417 bytes
    Fill with silence (zeros after header).
    """
    header = bytes([0xFF, 0xFB, 0x90, 0x00])
    frame_size = 417
    return header + bytes(frame_size - 4)

def make_caf_minimal():
    """Minimal Core Audio Format (.caf) file with PCM desc."""
    # CAF file header
    caff_header = b'caff' + u16be(1) + u16be(0)  # version=1, flags=0
    # Audio Description chunk
    # sample_rate (64-bit float, BE) for 44100: 0x40E5888000000000
    asbd = (bytes([0x40,0xE5,0x88,0x80,0x00,0x00,0x00,0x00])  # 44100.0 double BE
           + b'lpcm'      # format_id
           + u32be(0x0C)  # format_flags: kCAFLinearPCMFormatFlagIsFloat=0 | IsLittleEndian=0x02 | IsPacked=0x08
           + u32be(2)     # bytes_per_packet
           + u32be(1)     # frames_per_packet
           + u32be(1)     # channels_per_frame
           + u32be(16))   # bits_per_channel
    desc_chunk = b'desc' + struct.pack(">q", len(asbd)) + asbd
    # Audio Data chunk (8 bytes + data)
    data_chunk = b'data' + struct.pack(">q", 4 + 16) + u32be(0) + bytes(16)
    return caff_header + desc_chunk + data_chunk

def make_m4a_minimal():
    """
    Minimal M4A (ISOBMFF/MP4 container). ftyp + moov stubs.
    AudioToolbox will recognise the container and attempt to parse the moov box.
    """
    def box(fc, payload): return u32be(8+len(payload)) + fc + payload
    ftyp = box(b'ftyp', b'M4A ' + u32be(0) + b'M4A mp42isom')
    # Minimal moov (empty — triggers EOF in codec init, exercises header-parse path)
    moov = box(b'moov', b'')
    mdat = box(b'mdat', b'\x00' * 8)
    return ftyp + moov + mdat

def write_audio_seeds():
    wav  = make_wav_minimal()
    aiff = make_aiff_minimal()
    mp3  = make_mp3_minimal()
    caf  = make_caf_minimal()
    m4a  = make_m4a_minimal()

    seeds = {
        "valid.wav":           wav,
        "valid.aiff":          aiff,
        "valid.mp3":           mp3,
        "valid.caf":           caf,
        "valid.m4a":           m4a,
        # Corrupt RIFF size — integer overflow target
        "bad_size.wav":        b'RIFF' + u32le(0xFFFFFFFF) + wav[8:],
        # Truncated
        "truncated.wav":       wav[:16],
        "truncated.aiff":      aiff[:12],
        "truncated.mp3":       mp3[:4],
        "truncated.caf":       caf[:20],
        # Corrupt num_samples to max
        "overflow_frames.aiff": aiff[:14] + u32be(0xFFFFFFFF) + aiff[18:],
    }
    for name, data in seeds.items():
        (CORPUS / name).write_bytes(data)
    print(f"  wrote {len(seeds)} audio seeds")

# ── NSKeyedArchiver plist seeds ───────────────────────────────────────────────

def make_nskeyedarchiver_plist(depth=3):
    """
    Binary plist encoding an NSKeyedArchiver archive.
    Contains nested arrays/dicts to exercise recursive decode paths.
    Uses bplist00 binary format header which NSKeyedUnarchiver expects.
    We write a valid bplist00 with the $archiver key set to NSKeyedArchiver.
    """
    # Rather than hand-rolling binary plist (complex), write an ASCII plist
    # that NSKeyedUnarchiver will reject at format check but still parse the header.
    # This exercises the format-detection path.
    ascii_plist = b'<?xml version="1.0" encoding="UTF-8"?>\n'
    ascii_plist += b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    ascii_plist += b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    ascii_plist += b'<plist version="1.0"><dict>'
    ascii_plist += b'<key>$archiver</key><string>NSKeyedArchiver</string>'
    ascii_plist += b'<key>$version</key><integer>100000</integer>'
    ascii_plist += b'<key>$top</key><dict><key>root</key><integer>1</integer></dict>'
    ascii_plist += b'<key>$objects</key><array><string>$null</string>'
    # Nest some objects
    for i in range(depth):
        ascii_plist += b'<dict><key>NS.keys</key><array/><key>NS.objects</key><array/></dict>'
    ascii_plist += b'</array>'
    ascii_plist += b'</dict></plist>'
    return ascii_plist

def make_binary_plist_stub():
    """
    Minimal bplist00 binary with NSKeyedArchiver wrapper.
    bplist00 magic + trailer. Body is just a single string object "NSKeyedArchiver".
    Exercises the binary plist parser path in CFPropertyList.
    """
    # bplist00 magic
    magic = b'bplist00'
    # Object: string "NSKeyedArchiver" (0x5F = string with 15 chars)
    obj = b'\x5F' + b'NSKeyedArchiver'
    # Offset table: 1 object at offset 8
    offset_table = bytes([8])
    # Trailer (32 bytes): unused(5) + sortVersion(1) + offsetIntSize(1) + objectRefSize(1)
    #                     + numObjects(8) + topObject(8) + offsetTableOffset(8)
    num_objects = 1
    top_object  = 0
    offset_table_offset = 8 + len(obj)
    trailer = (b'\x00' * 5                    # unused
              + b'\x00'                        # sortVersion
              + b'\x01'                        # offsetIntSize (1 byte per offset)
              + b'\x01'                        # objectRefSize (1 byte per ref)
              + struct.pack(">Q", num_objects)
              + struct.pack(">Q", top_object)
              + struct.pack(">Q", offset_table_offset))
    return magic + obj + offset_table + trailer

def write_plist_seeds():
    xml_arc  = make_nskeyedarchiver_plist(depth=3)
    xml_deep = make_nskeyedarchiver_plist(depth=20)  # deep nesting
    bplist   = make_binary_plist_stub()

    seeds = {
        "valid_archive.plist":  xml_arc,
        "deep_archive.plist":   xml_deep,
        "binary_archive.plist": bplist,
        "truncated.plist":      xml_arc[:30],
        # Corrupt version number — class version check target
        "bad_version.plist":    xml_arc.replace(b'100000', b'999999'),
    }
    for name, data in seeds.items():
        (CORPUS / name).write_bytes(data)
    print(f"  wrote {len(seeds)} plist seeds")

# ── main ──────────────────────────────────────────────────────────────────────

def write_pdf_seeds():
    """PDF seeds — six targets for the PDFKit fuzzer surface."""
    minimal = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 44>>\nstream\n"
        b"BT /F1 12 Tf 100 700 Td (Hello) Tj ET\nendstream\nendobj\n"
        b"xref\n0 5\n"
        b"0000000000 65535 f\r\n0000000009 00000 n\r\n0000000058 00000 n\r\n"
        b"0000000115 00000 n\r\n0000000206 00000 n\r\n"
        b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n302\n%%EOF\n"
    )
    (CORPUS / "seed_minimal.pdf").write_bytes(minimal)

    font_stub = b"\x00\x01\x00\x00"  # sfnt version magic
    embedded = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
        b"/Resources<</Font<</F1 4 0 R>>>>>>endobj\n"
        b"4 0 obj<</Type/Font/Subtype/TrueType/BaseFont/TestFont"
        b"/FontDescriptor 5 0 R>>endobj\n"
        b"5 0 obj<</Type/FontDescriptor/FontName/TestFont/FontFile2 6 0 R>>endobj\n"
        b"6 0 obj<</Length " + str(len(font_stub)).encode() + b">>\nstream\n"
        + font_stub + b"\nendstream\nendobj\n"
        b"xref\n0 7\n"
        b"0000000000 65535 f\r\n0000000009 00000 n\r\n0000000058 00000 n\r\n"
        b"0000000115 00000 n\r\n0000000230 00000 n\r\n0000000320 00000 n\r\n"
        b"0000000400 00000 n\r\n"
        b"trailer<</Size 7/Root 1 0 R>>\nstartxref\n500\n%%EOF\n"
    )
    (CORPUS / "seed_embedded_ttf.pdf").write_bytes(embedded)
    (CORPUS / "seed_malformed_xref.pdf").write_bytes(
          minimal.replace(b"startxref\n302\n", b"startxref\n999999\n"))
    (CORPUS / "seed_truncated_stream.pdf").write_bytes(
          minimal.replace(b"<</Length 44>>", b"<</Length 9999>>"))
    (CORPUS / "seed_giant_pagecount.pdf").write_bytes(
          minimal.replace(b"/Count 1", b"/Count 2147483647"))
    bad_filter = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 10/Filter/NoSuchFilterXYZ>>\nstream\n0123456789\nendstream\nendobj\n"
        b"xref\n0 5\n"
        b"0000000000 65535 f\r\n0000000009 00000 n\r\n0000000058 00000 n\r\n"
        b"0000000115 00000 n\r\n0000000206 00000 n\r\n"
        b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n302\n%%EOF\n"
    )
    (CORPUS / "seed_bad_filter.pdf").write_bytes(bad_filter)


if __name__ == "__main__":
    print(f"gen_corpus.py v3: writing seeds to {CORPUS}")
    if not HAS_PILLOW:
        print("  (Pillow not available — using hand-crafted minimal bitstreams)")
    write_image_seeds()
    write_font_seeds()
    write_audio_seeds()
    write_plist_seeds()
    write_pdf_seeds()

    total = len([f for f in CORPUS.iterdir() if not f.name.startswith('.')])
    print(f"gen_corpus.py: {total} seed files total in corpus/")
