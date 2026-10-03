import SwiftUI
import AVFoundation

struct QRScanner: UIViewControllerRepresentable {
    var onScan: (String) -> Void
    func makeUIViewController(context: Context) -> ScannerController { ScannerController(onScan: onScan) }
    func updateUIViewController(_ uiViewController: ScannerController, context: Context) {}
}
final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "foxVPN.camera")
    private let onScan: (String) -> Void
    private var completed = false
    private var preview: AVCaptureVideoPreviewLayer?
    init(onScan: @escaping (String) -> Void) { self.onScan = onScan; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) unavailable") }
    override func viewDidLoad() {
        super.viewDidLoad(); view.backgroundColor = .black
        let label = UILabel(); label.text = "Наведите камеру на QR сервера"; label.textColor = .white; label.translatesAutoresizingMaskIntoConstraints = false; view.addSubview(label)
        NSLayoutConstraint.activate([label.centerXAnchor.constraint(equalTo: view.centerXAnchor), label.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -30)])
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            guard let self else { return }
            if granted { self.queue.async { self.configure() } }
            else { DispatchQueue.main.async { self.showError("Разрешите доступ к камере в настройках iPhone или вставьте ссылку вручную.") } }
        }
    }
    private func configure() {
        guard let camera = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: camera), session.canAddInput(input) else { DispatchQueue.main.async { self.showError("Камера недоступна. Используйте вставку ссылки или импорт файла.") }; return }
        session.beginConfiguration(); session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { session.commitConfiguration(); return }
        session.addOutput(output); output.setMetadataObjectsDelegate(self, queue: .main); output.metadataObjectTypes = [.qr]; session.commitConfiguration()
        DispatchQueue.main.async { let layer = AVCaptureVideoPreviewLayer(session: self.session); layer.videoGravity = .resizeAspectFill; self.view.layer.insertSublayer(layer, at: 0); self.preview = layer; layer.frame = self.view.bounds }
        session.startRunning()
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    override func viewDidDisappear(_ animated: Bool) { super.viewDidDisappear(animated); queue.async { self.session.stopRunning() } }
    private func showError(_ message: String) { let alert = UIAlertController(title: "Сканирование QR", message: message, preferredStyle: .alert); alert.addAction(UIAlertAction(title: "Закрыть", style: .default) { _ in self.dismiss(animated: true) }); present(alert, animated: true) }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !completed, let value = (metadataObjects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        guard value.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("vless://") else { completed = true; showError("Этот QR не содержит VLESS-ссылку."); return }
        completed = true; queue.async { self.session.stopRunning() }; onScan(value)
    }
}
