// Sources/Logger.swift
import Foundation
import os.log

final class Logger {
    static let shared = Logger()

    var onLine: ((String) -> Void)?

    private let queue = DispatchQueue(label: "com.venice.parasite.logger")
    private var handle: FileHandle?
    private var seq: UInt64 = 0
    private let osLog = OSLog(subsystem: "com.venice.parasite", category: "harness")
    private let logURL: URL

    private init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        logURL = docs.appendingPathComponent("harness.log")
        if !FileManager.default.fileExists(atPath: logURL.path) {
            FileManager.default.createFile(atPath: logURL.path, contents: nil)
        }
        handle = try? FileHandle(forWritingTo: logURL)
        handle?.seekToEndOfFile()
    }

    var fileURL: URL { logURL }

    func log(_ message: String) {
        let ts = String(format: "%.3f", Date().timeIntervalSince1970)
        let tid = Thread.isMainThread ? "main" : "bg"
        queue.sync {
            seq += 1
            let line = "[\(ts)] #\(seq) [\(tid)] \(message)\n"
            if let data = line.data(using: .utf8) {
                handle?.write(data)
            }
            os_log("%{public}@", log: osLog, type: .default, message)
            if let cb = onLine {
                DispatchQueue.main.async { cb(line) }
            }
        }
    }

    /// Async-signal-safe best-effort write (for crash handlers).
    func rawWrite(_ s: String) {
        guard let data = s.data(using: .utf8) else { return }
        // bypass queue — crash context, only one thread alive
        handle?.write(data)
    }

    func truncate() {
        queue.sync {
            handle?.truncateFile(atOffset: 0)
            handle?.seek(toFileOffset: 0)
            seq = 0
        }
    }
}
