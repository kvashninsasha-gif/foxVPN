import XCTest
import CoreImage.CIFilterBuiltins
import UIKit
@testable import FoxVPN

final class ImportAndTransferTests: XCTestCase {
    func testRealImageDecoderReadsGeneratedQRCodeAndRejectsOtherPayload() throws {
        let link = "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=tcp#PublicFixture"
        XCTAssertEqual(try QRImageReader.links(from: pngQR(link)), link)
        XCTAssertThrowsError(try QRImageReader.links(from: pngQR("not-a-vless-link")))
        XCTAssertThrowsError(try QRImageReader.links(from: Data("invalid".utf8)))
    }
    private func pngQR(_ text: String) throws -> Data {
        let filter = CIFilter.qrCodeGenerator(); filter.message = Data(text.utf8)
        let output = filter.outputImage!.transformed(by: .init(scaleX: 8, y: 8))
        return UIImage(cgImage: CIContext().createCGImage(output, from: output.extent)!).pngData()!
    }
    func testBoundedTransferCompletesExactBody() async throws {
        let value = try await transfer("complete").run(); XCTAssertGreaterThan(value, 0)
    }
    func testPartialOrOversizedBodyNeverBecomesSpeed() async {
        for path in ["partial", "large", "failure"] {
            do { _ = try await transfer(path).run(); XCTFail("Invalid transfer accepted") } catch {}
        }
    }
    func testTransferCancellationBeforeAndDuringStartAlwaysCompletes() async {
        let early = transfer("stall"); early.cancel()
        do { _ = try await early.run(); XCTFail("Cancellation ignored") } catch {}
        let late = transfer("stall"); let operation = Task { try await late.run() }; await Task.yield(); operation.cancel()
        do { _ = try await operation.value; XCTFail("Cancellation ignored") } catch {}
    }
    func testPublicSpeedServiceUsesRealHTTPSDownloadAndUpload() async throws {
        let result = try await HTTPSSpeedChecker().measure()
        XCTAssertGreaterThan(result.downloadMbps, 0); XCTAssertGreaterThan(result.uploadMbps, 0)
        XCTAssertTrue(result.downloadMbps.isFinite); XCTAssertTrue(result.uploadMbps.isFinite)
    }
    private func transfer(_ path: String) -> BoundedSpeedTransfer {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [TransferFixture.self]
        return BoundedSpeedTransfer(url: URL(string: "https://example.com/" + path)!, bytes: 1000, uploading: false, configuration: config)
    }
}
private final class TransferFixture: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "example.com" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path = request.url!.lastPathComponent
        if path == "stall" { return }
        let status = path == "failure" ? 500 : 200, count = path == "partial" ? 500 : path == "large" ? 2000 : 1000
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": String(count)])!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(repeating: 1, count: count)); client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
