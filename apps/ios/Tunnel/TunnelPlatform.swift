import Foundation
import Network
import NetworkExtension
import Libbox
import Darwin

final class TunnelPlatform: NSObject, LibboxPlatformInterfaceProtocol, LibboxCommandServerHandlerProtocol {
    private weak var provider: PacketTunnelProvider?
    private let pathQueue = DispatchQueue(label: "foxVPN.tunnel.path")
    private var monitor: NWPathMonitor?
    private let lock = NSLock()
    private var path: Network.NWPath?
    init(provider: PacketTunnelProvider) { self.provider = provider }
    private func unsupported() -> Error { FoxError.invalid("Эта системная операция не поддерживается в iOS.") }
    func openTun(_ options: LibboxTunOptionsProtocol?, ret0_: UnsafeMutablePointer<Int32>?) throws {
        guard let options, let ret0_, let provider else { throw unsupported() }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1"); settings.mtu = NSNumber(value: options.getMTU())
        var addresses4: [String] = [], masks4: [String] = []
        if let iterator = options.getInet4Address() { while iterator.hasNext() { if let prefix = iterator.next() { addresses4.append(prefix.address()); masks4.append(prefix.mask()) } } }
        let ipv4 = NEIPv4Settings(addresses: addresses4, subnetMasks: masks4)
        ipv4.includedRoutes = [NEIPv4Route.default()]; settings.ipv4Settings = ipv4
        var addresses6: [String] = [], prefixes6: [NSNumber] = []
        if let iterator = options.getInet6Address() { while iterator.hasNext() { if let prefix = iterator.next() { addresses6.append(prefix.address()); prefixes6.append(NSNumber(value: prefix.prefix())) } } }
        let ipv6 = NEIPv6Settings(addresses: addresses6, networkPrefixLengths: prefixes6)
        ipv6.includedRoutes = [NEIPv6Route.default()]; settings.ipv6Settings = ipv6
        let iterator = try options.getDNSServerAddress(); var servers: [String] = []
        while iterator.hasNext() { servers.append(iterator.next()) }
        guard !servers.isEmpty else { throw FoxError.invalid("Виртуальный DNS не задан.") }
        let dns = NEDNSSettings(servers: servers); dns.matchDomains = [""]; dns.matchDomainsNoSearch = true; settings.dnsSettings = dns
        let done = DispatchSemaphore(value: 0); var failure: Error?
        provider.setTunnelNetworkSettings(settings) { error in failure = error; done.signal() }
        guard done.wait(timeout: .now() + 15) == .success else { throw FoxError.invalid("iOS не применила сетевые настройки вовремя.") }
        if let failure { throw failure }
        // Upstream obtains the owned utun socket via getsockopt/getpeername; no private KVC.
        let fd = LibboxGetTunnelFileDescriptor(); guard fd >= 0 else { throw FoxError.invalid("Сетевой интерфейс iOS недоступен.") }; ret0_.pointee = fd
    }
    func startDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
        guard let listener else { throw unsupported() }
        let monitor = NWPathMonitor(); self.monitor = monitor; let first = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            self.lock.lock(); self.path = path; self.lock.unlock()
            let interface = path.availableInterfaces.first
            listener.updateNetworkPath(path.status == .satisfied ? "available" : "unavailable")
            listener.updateDefaultInterface(path.status == .satisfied ? interface?.name ?? "" : "", interfaceIndex: path.status == .satisfied ? Int32(interface?.index ?? 0) : -1, isExpensive: path.isExpensive, isConstrained: path.isConstrained)
            first.signal()
        }
        monitor.start(queue: pathQueue)
        guard first.wait(timeout: .now() + 10) == .success else { monitor.cancel(); throw FoxError.invalid("Не удалось определить сеть iPhone.") }
    }
    func closeDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws { shutdown() }
    func shutdown() { monitor?.cancel(); monitor = nil; lock.lock(); path = nil; lock.unlock() }
    func getInterfaces() throws -> LibboxNetworkInterfaceIteratorProtocol {
        lock.lock(); let path = self.path; lock.unlock()
        let values = (path?.availableInterfaces ?? []).map { item -> LibboxNetworkInterface in
            let result = LibboxNetworkInterface(); result.name = item.name; result.index = Int32(item.index); result.mtu = 1500; result.flags = Int32(IFF_UP | IFF_RUNNING)
            result.type = item.type == .wifi ? LibboxInterfaceTypeWIFI : item.type == .cellular ? LibboxInterfaceTypeCellular : item.type == .wiredEthernet ? LibboxInterfaceTypeEthernet : LibboxInterfaceTypeOther
            result.metered = path?.isExpensive ?? false; return result
        }
        return InterfaceIterator(values)
    }
    func usePlatformAutoDetectControl() -> Bool { false }
    func autoDetectControl(_ fd: Int32) throws {}
    func underNetworkExtension() -> Bool { true }
    func includeAllNetworks() -> Bool { (provider?.protocolConfiguration as? NETunnelProviderProtocol)?.includeAllNetworks ?? false }
    func localDNSTransport() -> LibboxLocalDNSTransportProtocol? {
        SystemDNS { [weak self] in
            guard let self else { return 0 }; self.lock.lock(); defer { self.lock.unlock() }
            guard self.path?.status == .satisfied else { return 0 }
            return UInt32(self.path?.availableInterfaces.first?.index ?? 0)
        }
    }
    func useProcFS() -> Bool { false }
    func readWIFIState() -> LibboxWIFIState? { nil }
    func clearDNSCache() {}
    func registerMyInterface(_ name: String?) {}
    func send(_ notification: LibboxNotification?) throws {}
    func cancelNotification(_ identifier: String?, typeID: Int32) throws {}
    func startNeighborMonitor(_ listener: LibboxNeighborUpdateListenerProtocol?) throws { throw unsupported() }
    func closeNeighborMonitor(_ listener: LibboxNeighborUpdateListenerProtocol?) throws {}
    func findConnectionOwner(_ ipProtocol: Int32, sourceAddress: String?, sourcePort: Int32, destinationAddress: String?, destinationPort: Int32) throws -> LibboxConnectionOwner { throw unsupported() }
    func usePlatformShell() -> Bool { false }
    func checkPlatformShell() throws { throw unsupported() }
    func openShellSession(_ user: LibboxPlatformUser?, command: String?, environ: LibboxStringIteratorProtocol?, term: String?, rows: Int32, cols: Int32) throws -> LibboxShellSessionProtocol { throw unsupported() }
    func lookupUser(_ username: String?) throws -> LibboxPlatformUser { throw unsupported() }
    func lookupSFTPServer(_ error: NSErrorPointer) -> String { error?.pointee = unsupported() as NSError; return "" }
    func readSystemSSHHostKey(_ error: NSErrorPointer) -> String { error?.pointee = unsupported() as NSError; return "" }
    func tailscaleHostname() -> String { "foxVPN" }
    func usePlatformBridge() -> Bool { false }
    func createBridge(_ options: LibboxBridgeOptions?) throws -> LibboxBridgeSessionProtocol { throw unsupported() }
    func serviceStop() throws { provider?.cancelTunnelWithError(nil) }
    func serviceReload() throws { throw unsupported() }
    func getSystemProxyStatus() throws -> LibboxSystemProxyStatus { LibboxSystemProxyStatus() }
    func setSystemProxyEnabled(_ enabled: Bool) throws { throw unsupported() }
    func triggerNativeCrash() throws { throw unsupported() }
    func writeDebugMessage(_ message: String?) {}
    func connectSSHAgent(_ ret0_: UnsafeMutablePointer<Int32>?) throws { throw unsupported() }
}
private final class InterfaceIterator: NSObject, LibboxNetworkInterfaceIteratorProtocol {
    let values: [LibboxNetworkInterface]; var index = 0
    init(_ values: [LibboxNetworkInterface]) { self.values = values }
    func hasNext() -> Bool { index < values.count }
    func next() -> LibboxNetworkInterface? { guard hasNext() else { return nil }; defer { index += 1 }; return values[index] }
}
