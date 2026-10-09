import SwiftUI

@main
struct KeywardenApp: App {
    @UIApplicationDelegateAdaptor(NotificationDelegate.self) private var notificationDelegate
    @StateObject private var model = ApprovalModel.applicationModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .onReceive(NotificationCenter.default.publisher(for: .keywardenDeviceToken)) { event in
                    if let token = event.object as? String { Task { await model.registerPush(token) } }
                }
        }
    }
}
