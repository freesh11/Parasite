// Sources/Parasite.swift
// lang: Swift, file: Parasite.swift, target: iOS 15+
// v14 — aggressive multi-surface fuzzer entry points (+ PDFKit surface).

import Foundation
import UIKit

// Shared stop flag — ViewController sets YES to abort both fuzzers.
// Must be ObjCBool so &gFuzzStop satisfies volatile BOOL * in the ObjC signatures.
var gFuzzStop: ObjCBool = false

func dumpEnvironment() {
    Logger.shared.log("device: \(UIDevice.current.name) iOS \(UIDevice.current.systemVersion)")
    Logger.shared.log("mode: multi-surface fuzzer v14 (ImageIO + CoreText + AudioToolbox + Unarchiver + PDFKit)")
}

// ── ImageIO fuzzer ────────────────────────────────────────────────────────────
// 300 iter/seed, 10 mutation ops max, aggressive field smashing.
func runImageFuzz(iterationsPerSeed: UInt = 300,
                  completion: @escaping () -> Void) {
    gFuzzStop = false
    Logger.shared.log("ImageFuzz: START iter/seed=\(iterationsPerSeed)")
    ImageFuzzRun(iterationsPerSeed,
        &gFuzzStop,
        { line in Logger.shared.log(line) },
        { hits in
            Logger.shared.log("ImageFuzz: DONE — \(hits.count) total hits")
            for h in hits {
                let kind = h.crashed ? "CRASH" : (h.nullImage ? "NIL" : "STATUS")
                Logger.shared.log(String(format: "  [%@] %@ iter=%lu: %@",
                    h.seedName, kind, h.iteration,
                    h.exceptionDesc ?? "(no desc)"))
            }
            completion()
        })
}

// ── PDF fuzzer (CGPDFDocument + PDFKit + EmbeddedFont) ───────────────────────
// Three concurrent PDF parse surfaces. EmbeddedFont is the chollima vector.
func runPDFFuzz(iterationsPerSeed: UInt = 300,
                completion: @escaping () -> Void) {
    gFuzzStop = false
    Logger.shared.log("PDFFuzz: START iter/seed=\(iterationsPerSeed) (CGPDF + PDFKit + EmbFont)")
    PDFFuzzRun(iterationsPerSeed,
        &gFuzzStop,
        { line in Logger.shared.log(line) },
        { hits in
            Logger.shared.log("PDFFuzz: DONE — \(hits.count) total hits")
            for h in hits {
                let kind = h.crashed ? "CRASH" : "HIT"
                Logger.shared.log(String(format: "  [%@] %@ seed=%@ iter=%lu: %@",
                    h.subsurface.rawValue == 0 ? "CGPDF" : (h.subsurface.rawValue == 1 ? "PDFKit" : "EmbFont"),
                    kind, h.seedName, h.iteration,
                    h.desc ?? "(no desc)"))
            }
            completion()
        })
}

// ── Multi-surface fuzzer (CoreText + AudioToolbox + Unarchiver) ───────────────
// Runs all 3 surfaces concurrently, 300 iter/seed each.
func runSurfaceFuzz(iterationsPerSeed: UInt = 300,
                    completion: @escaping () -> Void) {
    gFuzzStop = false
    Logger.shared.log("SurfaceFuzz: START iter/seed=\(iterationsPerSeed) (CoreText + AudioTB + Unarchive)")
    SurfaceFuzzRun(iterationsPerSeed,
        &gFuzzStop,
        { line in Logger.shared.log(line) },
        { hits in
            Logger.shared.log("SurfaceFuzz: DONE — \(hits.count) total hits")
            for h in hits {
                Logger.shared.log(String(format: "  [%@] seed=%@ iter=%lu: %@",
                    h.seedName, h.seedName, h.iteration,
                    h.desc ?? "(no desc)"))
            }
            completion()
        })
}

// ── Full aggressive scan — all surfaces in parallel ───────────────────────────
func runFullScan(completion: @escaping () -> Void) {
    gFuzzStop = false
    Logger.shared.log("FullScan: START — ImageIO + CoreText + AudioTB + Unarchiver + PDFKit (all parallel)")

    let group = DispatchGroup()

    group.enter()
    ImageFuzzRun(300,
        &gFuzzStop,
        { line in Logger.shared.log(line) },
        { hits in
            Logger.shared.log("FullScan: ImageIO done — \(hits.count) hits")
            group.leave()
        })

    group.enter()
    SurfaceFuzzRun(300,
        &gFuzzStop,
        { line in Logger.shared.log(line) },
        { hits in
            Logger.shared.log("FullScan: Surfaces done — \(hits.count) hits")
            group.leave()
        })

    group.enter()
    PDFFuzzRun(300,
        &gFuzzStop,
        { line in Logger.shared.log(line) },
        { hits in
            Logger.shared.log("FullScan: PDF done — \(hits.count) hits")
            group.leave()
        })

    group.notify(queue: .main) {
        Logger.shared.log("FullScan: ALL SURFACES COMPLETE")
        completion()
    }
}
