import SwiftUI

@main
struct PsstShareApp: App {
    var body: some Scene {
        WindowGroup("Psst Share") {
            Text("In 1Password, share an item and choose **Send to psst**.")
                .padding(24)
        }
        .windowResizability(.contentSize)
    }
}
