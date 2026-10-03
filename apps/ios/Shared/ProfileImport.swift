import Foundation

public enum ProfileImport {
    case links(String), profile(VPNProfile)
    public static func parse(_ data: Data) throws -> ProfileImport {
        guard data.count <= 4_000_000, var text = String(data: data, encoding: .utf8) else { throw FoxError.invalid("Файл слишком большой или имеет неподдерживаемую кодировку.") }
        if text.hasPrefix("\u{feff}") { text.removeFirst() }
        text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("vless://") { var value = VPNProfile(); _ = try value.importLinks(text); return .links(text) }
        guard text.hasPrefix("{") else { throw FoxError.invalid("Нужен JSON-профиль foxVPN или текст с VLESS-ссылками.") }
        do {
            var value = try JSONDecoder().decode(VPNProfile.self, from: Data(text.utf8)); try value.validate()
            value.rules = try value.rules.map { try $0.normalized() }; return .profile(value)
        } catch let error as FoxError { throw error }
        catch { throw FoxError.invalid("JSON-профиль повреждён или имеет неподдерживаемый формат. Текущий профиль сохранён.") }
    }
}

public enum AppMetadata {
    public static var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.1" }
    public static var build: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "2" }
}
