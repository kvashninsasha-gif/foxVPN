import Foundation

// The engine supplies one uncompressed DNS question. DNS-SD returns raw record data.
struct DNSMessage {
    let id: UInt16
    let name: String
    let type: UInt16
    let recordClass: UInt16
    let question: Data
    init(_ data: Data) throws {
        let bytes = Array(data)
        func word(_ offset: Int) -> UInt16 { UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1]) }
        guard bytes.count >= 17, word(4) == 1, word(2) & 0x8000 == 0 else { throw FoxError.invalid("Некорректный DNS-запрос.") }
        var cursor = 12, labels: [String] = []
        while cursor < bytes.count {
            let size = Int(bytes[cursor]); cursor += 1
            if size == 0 { break }
            guard size <= 63, cursor + size < bytes.count, let label = String(bytes: bytes[cursor..<(cursor + size)], encoding: .utf8), !label.contains(".") else { throw FoxError.invalid("Некорректное DNS-имя.") }
            labels.append(label); cursor += size
        }
        guard cursor + 4 <= bytes.count, cursor > 12, bytes[cursor - 1] == 0, !labels.isEmpty else { throw FoxError.invalid("Неполный DNS-запрос.") }
        id = word(0); name = labels.joined(separator: ".") + "."; type = word(cursor); recordClass = word(cursor + 2); question = Data(bytes[12..<(cursor + 4)])
    }
    static func wireName(_ name: String) throws -> Data {
        var result = Data()
        for label in name.split(separator: ".") {
            let bytes = Data(label.utf8); guard !bytes.isEmpty, bytes.count <= 63 else { throw FoxError.invalid("Некорректная DNS-запись.") }
            result.append(UInt8(bytes.count)); result.append(bytes)
        }
        result.append(0); guard result.count <= 255 else { throw FoxError.invalid("DNS-имя слишком длинное.") }; return result
    }
    func response(answers: [Data]) -> Data {
        var result = Data()
        for word in [id, 0x8180, 1, UInt16(answers.count), 0, 0] { result.append(UInt8(word >> 8)); result.append(UInt8(word & 255)) }
        result.append(question); answers.forEach { result.append($0) }; return result
    }
    static func answer(name: String, type: UInt16, recordClass: UInt16, ttl: UInt32, payload: Data) throws -> Data {
        guard payload.count <= 65535 else { throw FoxError.invalid("DNS-запись слишком большая.") }
        var result = try wireName(name)
        for word in [type, recordClass] { result.append(UInt8(word >> 8)); result.append(UInt8(word & 255)) }
        for shift in [24, 16, 8, 0] { result.append(UInt8((ttl >> shift) & 255)) }
        let size = UInt16(payload.count); result.append(UInt8(size >> 8)); result.append(UInt8(size & 255)); result.append(payload); return result
    }
}
