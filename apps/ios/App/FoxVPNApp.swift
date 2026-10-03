import SwiftUI

@main struct FoxVPNApp: App {
    @StateObject private var controller = VPNController()
    var body: some Scene { WindowGroup { ContentView().environmentObject(controller).tint(Color.foxOrange).preferredColorScheme(ProcessInfo.processInfo.arguments.contains("--ui-testing") && ProcessInfo.processInfo.arguments.contains("--ui-dark") ? .dark : nil) } }
}

extension Color {
    static let foxOrange = Color(uiColor: UIColor { $0.userInterfaceStyle == .dark ? UIColor(red: 1, green: 0.66, blue: 0.38, alpha: 1) : UIColor(red: 0.72, green: 0.27, blue: 0.06, alpha: 1) })
    static let foxButtonText = Color(uiColor: UIColor { $0.userInterfaceStyle == .dark ? UIColor(red: 0.09, green: 0.16, blue: 0.26, alpha: 1) : .white })
    static let foxNavy = Color(red: 0.09, green: 0.16, blue: 0.26)
    static let foxCanvas = Color(uiColor: .systemGroupedBackground)
}
