import SwiftUI

@main struct FoxVPNApp: App {
    @StateObject private var controller = VPNController()
    var body: some Scene { WindowGroup { ContentView().environmentObject(controller).tint(Color.foxOrange) } }
}

extension Color {
    static let foxOrange = Color(red: 0.72, green: 0.27, blue: 0.06)
    static let foxNavy = Color(red: 0.09, green: 0.16, blue: 0.26)
    static let foxCanvas = Color(uiColor: .systemGroupedBackground)
}
