import Foundation
import dnssd
import Libbox
#if FOXVPN_DNS_TESTS
@testable import FoxVPN
#endif

// Public DNS-SD API, scoped to the physical interface rather than the virtual DNS.
final class SystemDNS: NSObject, LibboxLocalDNSTransportProtocol {
    private let interfaceIndex: () -> UInt32
    init(interfaceIndex: @escaping () -> UInt32) { self.interfaceIndex = interfaceIndex }
    func raw() -> Bool { true }
    func lookup(_ ctx: LibboxExchangeContext?, network: String?, domain: String?) throws { throw FoxError.invalid("DNS требует полного запроса.") }
    func exchange(_ ctx: LibboxExchangeContext?, message: Data?) throws {
        guard let ctx, let message else { throw FoxError.invalid("Пустой DNS-запрос.") }
        let index = interfaceIndex(); guard index != 0 else { throw FoxError.invalid("Физическая сеть недоступна для DNS.") }
        let query = DNSQuery(question: try DNSMessage(message), interfaceIndex: index)
        ctx.onCancel(DNSCancellation(query))
        ctx.rawSuccess(try query.resolve())
    }
}
private final class DNSCancellation: NSObject, LibboxFuncProtocol {
    private weak var query: DNSQuery?
    init(_ query: DNSQuery) { self.query = query }
    func invoke() throws { query?.cancel() }
}
final class DNSQuery {
    private static let queue = DispatchQueue(label: "foxVPN.system.dns", qos: .userInitiated)
    private let question: DNSMessage
    private let interfaceIndex: UInt32
    private let done = DispatchSemaphore(value: 0)
    private var reference: DNSServiceRef?
    private var answers: [Data] = []
    private var finished = false
    private var failure: Error?
    init(question: DNSMessage, interfaceIndex: UInt32) { self.question = question; self.interfaceIndex = interfaceIndex }
    func resolve() throws -> Data {
        Self.queue.sync {
            guard !finished else { return }
            let status = DNSServiceQueryRecord(&reference, DNSServiceFlags(kDNSServiceFlagsTimeout), interfaceIndex, question.name, question.type, question.recordClass, { _, flags, _, status, name, type, recordClass, size, bytes, ttl, context in
                guard let context else { return }
                let query = Unmanaged<DNSQuery>.fromOpaque(context).takeUnretainedValue()
                if status == kDNSServiceErr_NoSuchRecord { query.finish(); return }
                guard status == kDNSServiceErr_NoError else { query.finish(NSError(domain: "DNSService", code: Int(status))); return }
                guard query.answers.count < 256 else { query.finish(FoxError.invalid("Слишком много DNS-записей.")); return }
                if flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0, let name, let bytes {
                    do { query.answers.append(try DNSMessage.answer(name: String(cString: name), type: type, recordClass: recordClass, ttl: ttl, payload: Data(bytes: bytes, count: Int(size)))) }
                    catch { query.finish(error); return }
                }
                if flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0 { query.finish() }
            }, Unmanaged.passUnretained(self).toOpaque())
            guard status == kDNSServiceErr_NoError, let reference else { finish(NSError(domain: "DNSService", code: Int(status))); return }
            let scheduled = DNSServiceSetDispatchQueue(reference, Self.queue)
            if scheduled != kDNSServiceErr_NoError { finish(NSError(domain: "DNSService", code: Int(scheduled))) }
        }
        if done.wait(timeout: .now() + 12) != .success { Self.queue.sync { finish(FoxError.invalid("DNS не ответил вовремя.")) } }
        return try Self.queue.sync { if let failure { throw failure }; return question.response(answers: answers) }
    }
    func cancel() { Self.queue.async { self.finish(URLError(.cancelled)) } }
    private func finish(_ error: Error? = nil) {
        guard !finished else { return }; finished = true; failure = error
        if let reference { DNSServiceRefDeallocate(reference); self.reference = nil }
        done.signal()
    }
}
