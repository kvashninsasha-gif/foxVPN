import Foundation
import ImageIO
import CoreImage

enum QRImageReader {
    static func links(from data: Data) throws -> String {
        guard data.count <= 20_000_000, let source = CGImageSourceCreateWithData(data as CFData, nil),
              let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let width = props[kCGImagePropertyPixelWidth] as? Int, let height = props[kCGImagePropertyPixelHeight] as? Int,
              width > 0, height > 0, width <= 20_000, height <= 20_000, width * height <= 40_000_000,
              let image = CGImageSourceCreateThumbnailAtIndex(source, 0, [kCGImageSourceCreateThumbnailFromImageAlways: true, kCGImageSourceCreateThumbnailWithTransform: true, kCGImageSourceThumbnailMaxPixelSize: 2048] as CFDictionary) else { throw FoxError.invalid("Нужен файл изображения до 20 МБ с QR сервера.") }
        guard let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: CIContext(options: [.useSoftwareRenderer: true]), options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else { throw FoxError.invalid("Чтение QR недоступно.") }
        let values = detector.features(in: CIImage(cgImage: image)).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.filter { $0.hasPrefix("vless://") }
        guard !values.isEmpty else { throw FoxError.invalid("На изображении не найден QR с VLESS-ссылкой.") }
        var profile = VPNProfile(); _ = try profile.importLinks(values.joined(separator: "\n"))
        return values.joined(separator: "\n")
    }
}
