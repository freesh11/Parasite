# README.md
# Parasite

Diagnostic iOS app that loads PNG files through every CoreGraphics / ImageIO path and records everything to a log file, `os_log`, and an on-screen console. Built as an exploit harness: it survives exceptions and crashes and dumps the process environment (including injected dylibs) so runs on jailbroken devices are attributable.

## Building on macOS

```bash
# Prerequisites: Xcode 14+, Python 3, XcodeGen
brew install xcodegen

# Build
./build.sh
# Produces Parasite.ipa in the project root
```

## GitHub Actions

Push to `main` or trigger manually. The workflow installs XcodeGen, generates test PNGs, builds unsigned, and uploads the IPA as an artifact.

## Installing with Sideloadly (Windows)

1. Download [Sideloadly](https://sideloadly.io/).
2. Connect your iOS device via USB.
3. Drag `Parasite.ipa` into Sideloadly.
4. Enter your Apple ID. You will need an **app-specific password** (generate one at [appleid.apple.com](https://appleid.apple.com) → Sign-In and Security → App-Specific Passwords).
5. Click Start.
6. On iOS 16+, enable **Developer Mode**: Settings → Privacy & Security → Developer Mode → toggle on and reboot.
7. Trust the signing profile: Settings → General → VPN & Device Management → tap the profile → Trust.

**Note:** Free Apple developer certificates expire after **7 days**. You must re-sideload weekly unless you have a paid developer account ($99/year).

## Reading the log

The log is written to `Documents/harness.log` (accessible via Files app when `UIFileSharingEnabled` is on). Key failure signatures:

| Signature | Meaning |
|-----------|---------|
| `return=nil` | A CG/ImageIO call returned NULL — the image could not be decoded at that stage. |
| `EXCEPTION` | An Objective-C exception was thrown and caught. The name, reason, and call stack follow. |
| `TRUNCATED` | A PNG chunk's declared length exceeds the bytes actually available in the file. |
| `crcOK=false` | The stored CRC32 of a chunk does not match the computed CRC32 — the chunk data is corrupt or tampered. |
| `SIGNAL` | A fatal signal (SIGSEGV, SIGBUS, etc.) was caught. Backtrace follows on stderr and in the log (best-effort). |
