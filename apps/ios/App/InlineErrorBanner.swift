import SwiftUI

struct InlineErrorBanner: View {
    @EnvironmentObject var vpn: VPNController
    var body: some View {
        if let error = vpn.error {
            Label(error, systemImage: "exclamationmark.circle").font(.subheadline).foregroundStyle(.red).frame(maxWidth: .infinity, alignment: .leading).padding(14).background(Color(uiColor: .secondarySystemGroupedBackground)).accessibilityIdentifier("inlineError")
        }
    }
}
