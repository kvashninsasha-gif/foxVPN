import Foundation

struct SubscriptionFetcher {
    static func fetch(_ url: URL) async throws -> String {
        guard url.scheme == "https", url.host != nil, url.user == nil, url.password == nil else { throw FoxError.invalid("Подписка должна иметь HTTPS-адрес.") }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 30
        let session = URLSession(configuration: config, delegate: HTTPSRedirectPolicy(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var data = Data()
        let (bytes, response) = try await session.bytes(from: url)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode), http.url?.scheme == "https" else { throw FoxError.invalid("Подписка недоступна по HTTPS.") }
        guard http.expectedContentLength <= 4_000_000 else { throw FoxError.invalid("Подписка слишком большая.") }
        for try await byte in bytes {
            try Task.checkCancellation(); data.append(byte)
            if data.count > 4_000_000 { throw FoxError.invalid("Подписка слишком большая.") }
        }
        return try SubscriptionContent.decode(data)
    }
}
final class HTTPSRedirectPolicy: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        guard let url = request.url, url.scheme == "https", url.host != nil, url.user == nil, url.password == nil else { completionHandler(nil); return }
        completionHandler(request)
    }
}
