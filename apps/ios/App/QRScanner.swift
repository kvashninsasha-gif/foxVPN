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
    private var visible = true
    private var requested = false
    private var preview: AVCaptureVideoPreviewLayer?
    init(onScan: @escaping (String) -> Void) { self.onScan = onScan; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) unavailable") }
    override func viewDidLoad() {
        super.viewDidLoad(); view.backgroundColor = .black
        let label = UILabel(); label.text = "Наведите камеру на QR сервера"; label.textColor = .white; label.translatesAutoresizingMaskIntoConstraints = false; view.addSubview(label)
        NSLayoutConstraint.activate([label.centerXAnchor.constraint(equalTo: view.centerXAnchor), label.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -30)])
        let close = UIButton(type: .system); close.setTitle("Закрыть", for: .normal); close.tintColor = .white; close.translatesAutoresizingMaskIntoConstraints = false; close.addTarget(self, action: #selector(closeScanner), for: .touchUpInside); view.addSubview(close)
        NSLayoutConstraint.activate([close.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -20), close.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16)])
    }
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated); visible = true
        guard !requested else { return }; requested = true
        #if targetEnvironment(simulator)
        showError("Камера недоступна в симуляторе. Используйте вставку ссылки или импорт файла.")
        #else
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            guard let self else { return }
            DispatchQueue.main.async { guard self.visible else { return }; if granted { self.queue.async { self.configure() } } else { self.showError("Разрешите доступ к камере в настройках iPhone или вставьте ссылку вручную.") } }

        }
        #endif
    }
    private func configure() {
        guard let camera = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: camera), session.canAddInput(input) else { DispatchQueue.main.async { self.showError("Камера недоступна. Используйте вставку ссылки или импорт файла.") }; return }
        session.beginConfiguration(); session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { session.commitConfiguration(); DispatchQueue.main.async { self.showError("Сканирование QR недоступно. Вставьте ссылку вручную.") }; return }
        session.addOutput(output); output.setMetadataObjectsDelegate(self, queue: .main); output.metadataObjectTypes = [.qr]; session.commitConfiguration()
        DispatchQueue.main.async { guard self.visible else { self.queue.async { self.session.stopRunning() }; return }; let layer = AVCaptureVideoPreviewLayer(session: self.session); layer.videoGravity = .resizeAspectFill; self.view.layer.insertSublayer(layer, at: 0); self.preview = layer; layer.frame = self.view.bounds }
        session.startRunning()
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    override func viewDidDisappear(_ animated: Bool) { super.viewDidDisappear(animated); visible = false; queue.async { self.session.stopRunning() } }
    @objc private func closeScanner() { dismiss(animated: true) }
    private func showError(_ message: String) { guard visible, presentedViewController == nil else { return }; let alert = UIAlertController(title: "Сканирование QR", message: message, preferredStyle: .alert); alert.addAction(UIAlertAction(title: "Закрыть", style: .default) { _ in self.dismiss(animated: true) }); present(alert, animated: true) }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !completed, let value = (metadataObjects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        do { _ = try VPNServer.parse(value) } catch { completed = true; queue.async { self.session.stopRunning() }; showError("Этот QR не содержит корректную VLESS-ссылку."); return }
        completed = true; queue.async { self.session.stopRunning() }; onScan(value)
    }
}
