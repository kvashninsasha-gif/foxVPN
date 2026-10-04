import Foundation

struct SpeedResult { let downloadMbps: Double; let uploadMbps: Double }
protocol SpeedChecking { func measure() async throws -> SpeedResult }
struct HTTPSSpeedChecker: SpeedChecking {
    func measure() async throws -> SpeedResult {
        let down = try await BoundedSpeedTransfer(url: URL(string: "https://speed.cloudflare.com/__down?bytes=5000000")!, bytes: 5_000_000, uploading: false).run()
        try Task.checkCancellation()
        let up = try await BoundedSpeedTransfer(url: URL(string: "https://speed.cloudflare.com/__up")!, bytes: 1_000_000, uploading: true).run()
        return SpeedResult(downloadMbps: down, uploadMbps: up)
    }
}
// Counts delivered bytes without retaining a downloaded body. Cancellation, callbacks,
// and start can race; only the owner of the continuation may complete the transfer.
final class BoundedSpeedTransfer: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private let url: URL
    private let bytes: Int
    private let uploading: Bool
    private let configuration: URLSessionConfiguration
    private var continuation: CheckedContinuation<Double, Error>?
    private var session: URLSession?
    private var task: URLSessionTask?
    private var cancelled = false
    private var started = false
    private var count = 0
    private var sent: Int64 = 0
    private var startTime = 0.0
    init(url: URL, bytes: Int, uploading: Bool, configuration: URLSessionConfiguration = .ephemeral) { self.url = url; self.bytes = bytes; self.uploading = uploading; self.configuration = configuration }
    func run() async throws -> Double {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { callback in
                lock.lock()
                guard !cancelled, !started, continuation == nil, bytes > 0, bytes <= 5_000_000 else { lock.unlock(); callback.resume(throwing: CancellationError()); return }
                started = true; continuation = callback; startTime = ProcessInfo.processInfo.systemUptime
                let config = configuration; config.timeoutIntervalForRequest = 15; config.timeoutIntervalForResource = 25
                config.urlCache = nil; config.connectionProxyDictionary = [:]
                let session = URLSession(configuration: config, delegate: self, delegateQueue: nil); self.session = session
                var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
                request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
                if uploading { request.httpMethod = "POST"; request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type") }
                let task: URLSessionTask = uploading ? session.uploadTask(with: request, from: Data(repeating: 0, count: bytes)) : session.dataTask(with: request)
                self.task = task; lock.unlock(); task.resume()
            }
        } onCancel: { self.cancel() }
    }
    func cancel() { lock.lock(); cancelled = true; lock.unlock(); finish(.failure(CancellationError())) }
    private func finish(_ result: Result<Double, Error>) {
        lock.lock(); let callback = continuation; continuation = nil; let session = session; self.session = nil; task = nil; lock.unlock()
        session?.invalidateAndCancel(); callback?.resume(with: result)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        let limit = uploading ? 1024 : bytes
        guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url?.host == url.host,
              http.expectedContentLength <= Int64(limit) else { finish(.failure(FoxError.invalid("Сервис измерения вернул неподдерживаемый ответ."))); completionHandler(.cancel); return }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock(); guard continuation != nil else { lock.unlock(); return }
        count += data.count; let tooLarge = count > (uploading ? 1024 : bytes); lock.unlock()
        if tooLarge { finish(.failure(FoxError.invalid("Сервис измерения превысил ограничение трафика."))) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didSendBodyData bytesSent: Int64, totalBytesSent: Int64, totalBytesExpectedToSend: Int64) {
        lock.lock(); sent = totalBytesSent; lock.unlock()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure(error)); return }
        lock.lock(); let transferred = uploading ? sent : Int64(count); let elapsed = ProcessInfo.processInfo.systemUptime - startTime; lock.unlock()
        guard transferred == Int64(bytes), elapsed > 0 else { finish(.failure(FoxError.invalid("Измерение не завершено. Частичные данные не считаются скоростью."))); return }
        finish(.success(Double(bytes) * 8 / elapsed / 1_000_000))
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
