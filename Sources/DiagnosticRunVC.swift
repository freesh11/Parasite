// DiagnosticRunVC.swift
// lang: Swift, file: DiagnosticRunVC.swift, target: iOS 16+
// UI tab — CVE-2026-112706 file-read chain.
// Mirrors the fuzz-tab layout: preset picker + log scroll + run/stop button.

import UIKit

final class DiagnosticRunVC: UIViewController {

    // MARK: - UI

    private let picker      = UIPickerView()
    private let pathField   = UITextField()
    private let runButton   = UIButton(type: .system)
    private let clearButton = UIButton(type: .system)
    private let logView     = UITextView()
    private let statusLabel = UILabel()

    private var isRunning   = false
    private var logLines    = [String]()

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "DiagnosticRun"
        view.backgroundColor = .systemBackground
        setupUI()
    }

    private func setupUI() {
        // picker
        picker.dataSource = self
        picker.delegate   = self
        picker.translatesAutoresizingMaskIntoConstraints = false

        // custom path field
        pathField.placeholder = "Custom path (absolute)"
        pathField.borderStyle = .roundedRect
        pathField.font        = .monospacedSystemFont(ofSize: 12, weight: .regular)
        pathField.autocorrectionType     = .no
        pathField.autocapitalizationType = .none
        pathField.translatesAutoresizingMaskIntoConstraints = false

        // run button
        runButton.setTitle("Run", for: .normal)
        runButton.titleLabel?.font = .boldSystemFont(ofSize: 17)
        runButton.addTarget(self, action: #selector(runTapped), for: .touchUpInside)
        runButton.translatesAutoresizingMaskIntoConstraints = false

        // clear button
        clearButton.setTitle("Clear", for: .normal)
        clearButton.addTarget(self, action: #selector(clearTapped), for: .touchUpInside)
        clearButton.translatesAutoresizingMaskIntoConstraints = false

        // status
        statusLabel.font          = .monospacedSystemFont(ofSize: 12, weight: .regular)
        statusLabel.textColor     = .secondaryLabel
        statusLabel.text          = "idle"
        statusLabel.translatesAutoresizingMaskIntoConstraints = false

        // log view
        logView.isEditable   = false
        logView.font         = .monospacedSystemFont(ofSize: 11, weight: .regular)
        logView.backgroundColor = .systemGroupedBackground
        logView.layer.cornerRadius = 6
        logView.translatesAutoresizingMaskIntoConstraints = false

        // button row
        let btnRow = UIStackView(arrangedSubviews: [runButton, clearButton])
        btnRow.spacing = 16
        btnRow.translatesAutoresizingMaskIntoConstraints = false

        // assemble
        [picker, pathField, btnRow, statusLabel, logView].forEach { view.addSubview($0) }

        let g = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            picker.topAnchor.constraint(equalTo: g.topAnchor, constant: 8),
            picker.leadingAnchor.constraint(equalTo: g.leadingAnchor, constant: 16),
            picker.trailingAnchor.constraint(equalTo: g.trailingAnchor, constant: -16),
            picker.heightAnchor.constraint(equalToConstant: 120),

            pathField.topAnchor.constraint(equalTo: picker.bottomAnchor, constant: 4),
            pathField.leadingAnchor.constraint(equalTo: g.leadingAnchor, constant: 16),
            pathField.trailingAnchor.constraint(equalTo: g.trailingAnchor, constant: -16),

            btnRow.topAnchor.constraint(equalTo: pathField.bottomAnchor, constant: 8),
            btnRow.centerXAnchor.constraint(equalTo: view.centerXAnchor),

            statusLabel.topAnchor.constraint(equalTo: btnRow.bottomAnchor, constant: 4),
            statusLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),

            logView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 8),
            logView.leadingAnchor.constraint(equalTo: g.leadingAnchor, constant: 8),
            logView.trailingAnchor.constraint(equalTo: g.trailingAnchor, constant: -8),
            logView.bottomAnchor.constraint(equalTo: g.bottomAnchor, constant: -8),
        ])
    }

    // MARK: - Actions

    @objc private func runTapped() {
        guard !isRunning else {
            // stop not supported for sync chain — just indicate
            statusLabel.text = "chain is synchronous — wait for it"
            return
        }

        let row    = picker.selectedRow(inComponent: 0)
        var target = DiagnosticTarget.presets[row]
        let custom = pathField.text?.trimmingCharacters(in: .whitespaces) ?? ""

        if target.path.isEmpty && custom.isEmpty {
            statusLabel.text = "enter a path"
            return
        }

        // if "Custom path…" is selected, build a synthetic target from the field
        if target.path.isEmpty {
            let isDir = custom.hasSuffix("/")
            let path  = isDir ? String(custom.dropLast()) : custom
            target = .init(label: "custom", path: path, isDir: isDir)
        }

        isRunning = true
        runButton.setTitle("Running…", for: .normal)
        runButton.isEnabled = false
        statusLabel.text = "running"

        DiagnosticFetch.run(target: target, customPath: nil, log: { [weak self] line in
            DispatchQueue.main.async { self?.appendLog(line) }
        }, completion: { [weak self] result in
            guard let self else { return }
            self.isRunning       = false
            self.runButton.setTitle("Run", for: .normal)
            self.runButton.isEnabled = true
            self.statusLabel.text = result.files.isEmpty
                ? "failed — see log"
                : String(format: "done — %d file(s) in %.2fs", result.files.count, result.elapsed)
        })
    }

    @objc private func clearTapped() {
        logLines.removeAll()
        logView.text = ""
    }

    private func appendLog(_ line: String) {
        logLines.append(line)
        logView.text = logLines.joined(separator: "\n")
        let bottom = NSRange(location: logView.text.count - 1, length: 1)
        logView.scrollRangeToVisible(bottom)
    }
}

// MARK: - UIPickerViewDataSource / Delegate

extension DiagnosticRunVC: UIPickerViewDataSource, UIPickerViewDelegate {
    func numberOfComponents(in pickerView: UIPickerView) -> Int { 1 }
    func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
        DiagnosticTarget.presets.count
    }
    func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
        DiagnosticTarget.presets[row].label
    }
    func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int) {
        let target = DiagnosticTarget.presets[row]
        pathField.isHidden = target.path.isEmpty  // hide when preset has a path; show for Custom
    }
}
