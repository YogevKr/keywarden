import SwiftUI

struct SettingsView: View {
    @ObservedObject var model: ApprovalModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var replacingConnection = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(model.settings.isConfigured ? "Mac paired" : "Connect your Mac").font(.headline)
                            Text(model.settings.isConfigured ? "This iPhone can review requests from your Mac." : "Scan the setup QR shown on your Mac.")
                                .font(.subheadline).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: model.settings.isConfigured ? "checkmark.shield.fill" : "qrcode.viewfinder")
                            .foregroundStyle(.blue)
                    }.padding(.vertical, 6)
                    if model.settings.isConfigured {
                        LabeledContent("Last sync") {
                            if let sync = model.lastSync {
                                Text(sync, style: .relative)
                            } else {
                                Text("Waiting for sync")
                            }
                        }
                        Button { replacingConnection = true } label: {
                            Label("Pair another Mac", systemImage: "qrcode.viewfinder")
                        }.accessibilityIdentifier("scanSetupQR")
                    } else {
                        Button { model.showingScanner = true } label: {
                            Label("Scan setup QR", systemImage: "qrcode.viewfinder")
                        }.accessibilityIdentifier("scanSetupQR")
                    }
                } header: { Text("Connection") }
                .disabled(model.busyID != nil)

                Section {
                    LabeledContent("iPhone permission") {
                        Text(model.notificationPermission.title)
                            .foregroundStyle(model.notificationPermission == .enabled ? Color.green : Color.secondary)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("iPhone permission")
                    .accessibilityValue(model.notificationPermission.title)
                    .accessibilityIdentifier("notificationPermission")
                    if model.notificationPermission == .notRequested {
                        Button { Task { await model.enableNotifications() } } label: {
                            HStack {
                                Label("Enable notifications", systemImage: "bell.badge")
                                if model.requestingNotifications { Spacer(); ProgressView() }
                            }
                        }
                        .disabled(model.requestingNotifications)
                        .accessibilityIdentifier("enableNotifications")
                    } else if model.notificationPermission.canOpenSettings {
                        Button {
                            if let url = URL(string: UIApplication.openNotificationSettingsURLString) {
                                UIApplication.shared.open(url)
                            }
                        } label: {
                            Label(model.notificationPermission == .enabled ? "Notification settings" : "Open notification settings",
                                  systemImage: "arrow.up.forward.app")
                        }.accessibilityIdentifier("openNotificationSettings")
                    }
                    if let error = model.notificationError {
                        Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                        Button("Retry registration") { Task { await model.refreshNotificationState() } }
                            .disabled(!model.settings.isConfigured || !model.notificationPermission.canRegister)
                    }
                } header: { Text("Notifications") } footer: {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(model.notificationPermission.guidance)
                        Text("Alerts contain no vault names, item names, or secret values. Your Mac must remain online to send alerts.")
                    }
                }

                Section {
                    Label("Face ID for every decision", systemImage: "faceid")
                    Label("Encrypted approval requests", systemImage: "lock.shield")
                } header: { Text("Security") } footer: {
                    Text("Approval, denial, and revocation require biometric authentication. History stays on this iPhone.")
                }

                Section {
                    NavigationLink { ConnectionSettingsView(model: model) } label: {
                        Label("Advanced connection", systemImage: "slider.horizontal.3")
                    }.accessibilityIdentifier("advancedConnection")
                    LabeledContent("Version", value: "\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0") (\(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? ""))")
                } header: { Text("About") }

                if let error = model.errorMessage {
                    Section { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                }
            }
            .navigationTitle("Settings").navigationBarTitleDisplayMode(.inline)
            .task { await model.refreshNotificationState() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { Task { await model.refreshNotificationState() } }
            }
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .alert("Replace this Mac connection?", isPresented: $replacingConnection) {
                Button("Cancel", role: .cancel) {}
                Button("Scan new setup QR") { model.showingScanner = true }
            } message: {
                Text("A successful scan replaces the current connection. Cancelling keeps it unchanged.")
            }
            .sheet(isPresented: $model.showingScanner) {
                NavigationStack {
                    QRScannerView { value in
                        model.showingScanner = false
                        Task { await model.applySetupQR(value) }
                    }
                    .navigationTitle("Scan setup QR").navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { model.showingScanner = false } } }
                }
            }
        }
    }
}

private struct ConnectionSettingsView: View {
    @ObservedObject var model: ApprovalModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft: Settings

    init(model: ApprovalModel) {
        self.model = model
        _draft = State(initialValue: model.settings)
    }

    var body: some View {
        Form {
            Section {
                TextField("Relay URL", text: $draft.relayURL).keyboardType(.URL)
                SecureField("Relay token", text: $draft.relayToken)
                TextField("Broker ID", text: $draft.brokerID)
                TextField("Phone ID", text: $draft.phoneID)
                TextField("Broker signing key", text: $draft.brokerSigningPublicJWK, axis: .vertical).lineLimit(2...5)
                TextField("Broker encryption key", text: $draft.brokerEncryptionPublicJWK, axis: .vertical).lineLimit(2...5)
            } footer: {
                Text("Use QR setup unless you need to repair a connection. Changes apply only when you save.")
            }
            if let error = model.errorMessage { Section { Text(error).foregroundStyle(.orange) } }
        }
        .textInputAutocapitalization(.never).autocorrectionDisabled()
        .navigationTitle("Advanced connection").navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") {
                    let previous = model.settings
                    model.stopPolling()
                    model.settings = draft
                    if model.saveSettings() {
                        model.lastSync = nil
                        model.startPolling()
                        Task { await model.refreshNotificationState() }
                        dismiss()
                    } else {
                        model.settings = previous
                        model.startPolling()
                    }
                }.disabled(model.busyID != nil || !draft.isConfigured)
            }
        }
    }
}
