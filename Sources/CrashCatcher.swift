// Sources/CrashCatcher.swift
import Foundation
import Darwin

func installCrashHandlers() {
    NSSetUncaughtExceptionHandler { exception in
        let name = exception.name.rawValue
        let reason = exception.reason ?? "(nil)"
        let stack = exception.callStackSymbols.joined(separator: "\n")
        let msg = "EXCEPTION name=\(name) reason=\(reason)\n\(stack)\n"
        Logger.shared.rawWrite(msg)
    }

    let signals: [Int32] = [SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP]
    for sig in signals {
        signal(sig) { caught in
            let header = "SIGNAL \(caught) caught\n"
            // raw write to log
            Logger.shared.rawWrite(header)

            // backtrace to stderr (fd 2) — async-signal-safe
            var bt = [UnsafeMutableRawPointer?](repeating: nil, count: 128)
            let count = backtrace(&bt, Int32(bt.count))
            backtrace_symbols_fd(&bt, count, STDERR_FILENO)

            // reset and re-raise
            Darwin.signal(caught, SIG_DFL)
            raise(caught)
        }
    }
}
