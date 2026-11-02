// Sources/ViewController.swift
// v13 — buttons: Image | Surface | PDF | ALL | Stop | Share | Clear
import UIKit

final class ViewController: UIViewController {

    private let textView  = UITextView()
    private var buttons:  [UIButton] = []
    private let buttonBar = UIStackView()
    private var isFuzzing = false

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Parasite v13"
        view.backgroundColor = .systemBackground

        textView.isEditable = false
        textView.font = UIFont.monospacedSystemFont(ofSize: 9, weight: .regular)
        textView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(textView)

        // Image | Surface | PDF | ALL | Stop | Share | Clear
        for t in ["Image", "Surface", "PDF", "ALL", "Stop", "Share", "Clear"] {
            let b = UIButton(type: .system)
            b.setTitle(t, for: .normal)
            b.titleLabel?.font = UIFont.systemFont(ofSize: 12, weight: .medium)
            b.addTarget(self, action: #selector(buttonTapped(_:)), for: .touchUpInside)
            buttons.append(b)
        }
        buttonBar.axis = .horizontal
        buttonBar.distribution = .fillEqually
        buttonBar.translatesAutoresizingMaskIntoConstraints = false
        for b in buttons { buttonBar.addArrangedSubview(b) }
        view.addSubview(buttonBar)

        NSLayoutConstraint.activate([
            buttonBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            buttonBar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            buttonBar.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            buttonBar.heightAnchor.constraint(equalToConstant: 34),

            textView.topAnchor.constraint(equalTo: buttonBar.bottomAnchor),
            textView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            textView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        Logger.shared.onLine = { [weak self] line in self?.appendLine(line) }
        dumpEnvironment()
    }

    private func appendLine(_ line: String) {
        // Guard against corrupt NSStrings from fuzz callbacks causing __CFToUTF8 null-write crash.
        let safe: String
        if line.isContiguousUTF8 {
            safe = line
        } else {
            safe = line.unicodeScalars.reduce(into: "") { $0.unicodeScalars.append($1) }
        }
        var text = (textView.text ?? "") + safe
        if text.count > 400_000 { text = String(text.suffix(200_000)) }
        textView.text = text
        let range = NSRange(location: text.count - 1, length: 1)
        textView.scrollRangeToVisible(range)
    }

    @objc private func buttonTapped(_ sender: UIButton) {
        switch sender.currentTitle {
        case "Image":   start { runImageFuzz(completion: $0) }
        case "Surface": start { runSurfaceFuzz(completion: $0) }
        case "PDF":     start { runPDFFuzz(completion: $0) }
        case "ALL":     start { runFullScan(completion: $0) }
        case "Stop":    stopFuzz()
        case "Share":   shareLog(sender: sender)
        case "Clear":   clearLog()
        default: break
        }
    }

    private func start(block: @escaping (@escaping () -> Void) -> Void) {
        guard !isFuzzing else { return }
        isFuzzing = true
        setFuzzButtons(enabled: false)
        setButton("Stop", enabled: true)
        block { [weak self] in
            self?.isFuzzing = false
            self?.setFuzzButtons(enabled: true)
            self?.setButton("Stop", enabled: false)
        }
    }

    private func stopFuzz() {
        gFuzzStop = true
        Logger.shared.log("STOP requested")
        setButton("Stop", enabled: false)
    }

    private func shareLog(sender: UIView) {
        let ac = UIActivityViewController(activityItems: [Logger.shared.fileURL],
                                          applicationActivities: nil)
        if let pop = ac.popoverPresentationController {
            pop.sourceView = sender; pop.sourceRect = sender.bounds
        }
        present(ac, animated: true)
    }

    private func clearLog() {
        textView.text = ""
        Logger.shared.truncate()
    }

    private func setButton(_ title: String, enabled: Bool) {
        buttons.first(where: { $0.currentTitle == title })?.isEnabled = enabled
    }

    private func setFuzzButtons(enabled: Bool) {
        for t in ["Image", "Surface", "PDF", "ALL"] { setButton(t, enabled: enabled) }
    }
}
