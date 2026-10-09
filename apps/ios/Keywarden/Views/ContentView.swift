import SwiftUI

struct ContentView: View {
    @ObservedObject var model: ApprovalModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var showingSettings = false
    @State private var selectedRecord: ApprovalRecord?
    @ObservedObject private var notificationInbox = NotificationInbox.shared

    var body: some View {
        NavigationStack {
            TimelineView(.periodic(from: .now, by: 1)) { timeline in
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        header(at: timeline.date)
                        if let error = model.errorMessage {
                            Label(error, systemImage: "exclamationmark.triangle.fill")
                                .font(.subheadline).foregroundStyle(.orange)
                                .padding(16).frame(maxWidth: .infinity, alignment: .leading).card()
                                .accessibilityIdentifier("connectionError")
                        }
                        if !model.message.isEmpty {
                            Text(model.message).font(.subheadline).foregroundStyle(.secondary)
                                .accessibilityIdentifier("statusMessage")
                        }
                        if !model.settings.isConfigured { setupCard }
                        else if model.requests.isEmpty { emptyCard }
                        else {
                            sectionTitle("Needs approval", count: model.requests.count)
                            ForEach(model.requests) { request in
                                RequestCard(request: request, now: timeline.date, busy: model.busyID != nil,
                                    approve: { Task { await model.approve(request) } },
                                    deny: { Task { await model.deny(request) } })
                            }
                        }
                        let sessions = model.history.filter { ["active", "confirming", "revoking"].contains($0.state(at: timeline.date)) }
                        if !sessions.isEmpty {
                            VStack(alignment: .leading, spacing: 12) {
                                sectionTitle("Sessions", count: sessions.count)
                                ForEach(sessions) { record in
                                    SessionCard(record: record, date: timeline.date, busy: model.busyID != nil,
                                        revoke: { Task { await model.revoke(record) } }, details: { selectedRecord = record })
                                }
                            }
                        }
                        historySection(at: timeline.date)
                        Label("History stays on this iPhone", systemImage: "lock.fill")
                            .font(.caption).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity).padding(.bottom, 12)
                    }
                    .padding(20)
                }
                .background(Color(.systemGroupedBackground))
                .refreshable { await model.poll() }
            }
            .navigationTitle("Keywarden")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showingSettings = true } label: {
                        Image(systemName: "gearshape.fill").font(.body).padding(8).background(.blue.opacity(0.08), in: Circle())
                    }.accessibilityLabel("Settings").accessibilityIdentifier("settingsButton")
                }
            }
            .sheet(isPresented: $showingSettings) { SettingsView(model: model) }
            .sheet(item: $model.presentedRequest) { request in
                NavigationStack {
                    ApprovalReview(request: request, busy: model.busyID != nil,
                        error: model.errorMessage,
                        approve: { Task { await model.approve(request) } },
                        deny: { Task { await model.deny(request) } })
                        .task { if scenePhase == .active { await model.performNotificationAction(for: request.id) } }
                        .onChange(of: scenePhase) { _, phase in
                            if phase == .active { Task { await model.performNotificationAction(for: request.id) } }
                        }
                }
            }
            .sheet(item: $selectedRecord) { record in
                NavigationStack {
                    ScrollView { AccessDetails(request: record.request).padding(24) }
                        .navigationTitle("Approval details").navigationBarTitleDisplayMode(.inline)
                        .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { selectedRecord = nil } } }
                }
            }
            .task { model.prepareNotificationPreview(); model.startPolling(); await openNotificationIfReady() }
            .onChange(of: notificationInbox.route) { _, _ in Task { await openNotificationIfReady() } }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active {
                    model.prepareNotificationPreview()
                    model.startPolling()
                    Task { await openNotificationIfReady() }
                } else { model.stopPolling() }
            }
        }
        .tint(.blue)
    }

    @MainActor
    private func openNotificationIfReady() async {
        guard scenePhase == .active, let route = notificationInbox.take() else { return }
        showingSettings = false
        selectedRecord = nil
        await model.openNotification(route)
    }

    private func header(at date: Date) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Your access").font(.largeTitle.bold())
                Spacer()
                let connected = model.lastSync.map { date.timeIntervalSince($0) < 20 } ?? false
                HStack(spacing: 5) {
                    Circle().fill(connected ? Color.green : Color.secondary).frame(width: 6, height: 6)
                    Text(connected ? "Connected" : "Not connected").font(.caption.weight(.medium))
                }.foregroundStyle(.secondary)
            }
            Text(model.requests.isEmpty ? "Review access and past decisions." : "Review each request before you approve.")
                .font(.subheadline).foregroundStyle(.secondary)
        }
    }

    private var emptyCard: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.shield.fill").font(.system(size: 38)).foregroundStyle(.blue)
                .padding(20).background(.blue.opacity(0.08), in: Circle())
            Text("No pending requests").font(.title3.bold())
            Text("New approval requests appear here.")
                .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button { Task { await model.poll() } } label: {
                Label("Refresh now", systemImage: "arrow.clockwise")
            }.buttonStyle(.bordered).disabled(model.busyID != nil)
        }.frame(maxWidth: .infinity).padding(.vertical, 32).padding(.horizontal, 16).card()
        .accessibilityIdentifier("emptyRequests")
    }

    private var setupCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Image(systemName: "qrcode.viewfinder").font(.largeTitle).foregroundStyle(.blue)
            Text("Connect your Mac").font(.title2.bold())
            Text("Scan the setup QR to start receiving approval requests.").foregroundStyle(.secondary)
            Button("Set up Keywarden") { showingSettings = true }.buttonStyle(.borderedProminent)
        }.padding(24).frame(maxWidth: .infinity, alignment: .leading).card()
    }

    private func historySection(at date: Date) -> some View {
        let records = model.history.filter { !["active", "confirming", "revoking"].contains($0.state(at: date)) }
        return VStack(alignment: .leading, spacing: 12) {
            sectionTitle("History", count: records.count)
            if records.isEmpty {
                HStack(spacing: 14) {
                    Image(systemName: "clock.arrow.circlepath").font(.title2).foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("No past decisions").font(.subheadline.weight(.semibold))
                        Text("Approved and denied requests appear here.").font(.caption).foregroundStyle(.secondary)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(20).card()
            } else {
                VStack(spacing: 0) {
                    ForEach(records) { record in
                        Button { selectedRecord = record } label: { HistoryRow(record: record, date: date) }
                            .buttonStyle(.plain)
                        if record.id != records.last?.id { Divider().padding(.leading, 62) }
                    }
                }.card()
            }
        }.accessibilityIdentifier("approvalHistory")
    }
}

private struct ApprovalReview: View {
    let request: DecodedRequest
    let busy: Bool
    let error: String?
    let approve: () -> Void
    let deny: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Review access").font(.largeTitle.bold())
                    Text("Check the scope before you approve this request.")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                AccessDetails(request: request.request)
                if let error { Text(error).font(.subheadline).foregroundStyle(.orange) }
                if busy { Label("Confirm with Face ID", systemImage: "faceid").foregroundStyle(.blue) }
                HStack(spacing: 12) {
                    Button("Deny", role: .destructive, action: deny)
                        .frame(maxWidth: .infinity).buttonStyle(.bordered).tint(.red).controlSize(.large)
                    Button(action: approve) {
                        Label("Approve", systemImage: "faceid").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .accessibilityIdentifier("notificationApproveRequest")
                }
                .disabled(busy)
            }
            .padding(24)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Approval details")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct RequestCard: View {
    let request: DecodedRequest
    let now: Date
    let busy: Bool
    let approve: () -> Void
    let deny: () -> Void

    var body: some View {
        let expired = (parseDate(request.request.expiresAt) ?? .distantPast) <= now
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                Image(systemName: "terminal.fill").font(.title2).foregroundStyle(.blue)
                    .frame(width: 48, height: 48).background(.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 14))
                VStack(alignment: .leading, spacing: 4) {
                    Text(clientDisplayName(request.request)).font(.headline).textSelection(.enabled)
                    Text(clientSubtitle(request.request)).font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                Text(duration(request.request.durationSeconds)).font(.caption.weight(.semibold))
                    .padding(.horizontal, 10).padding(.vertical, 6).background(.blue.opacity(0.08), in: Capsule())
            }
            IntentDetails(request: request.request)
            Divider()
            ClientDetails(client: request.request.client, fallbackAgent: request.request.agent, fallbackHost: request.request.host)
            Divider()
            ScopeDetails(scope: request.request.scope)
            HStack(spacing: 6) {
                Image(systemName: "timer")
                Text(expired ? "Request expired" : "Idle limit: \(duration(request.request.idleTimeoutSeconds))")
            }.font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 12) {
                Button("Deny", role: .destructive, action: deny)
                    .frame(maxWidth: .infinity).buttonStyle(.bordered).tint(.red).controlSize(.large)
                Button(action: approve) { Label("Approve", systemImage: "faceid").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).controlSize(.large).accessibilityIdentifier("approveRequest")
            }.disabled(busy || expired)
        }.padding(20).card()
        .overlay(RoundedRectangle(cornerRadius: 22).stroke(.blue.opacity(0.2), lineWidth: 1))
    }
}

private struct SessionCard: View {
    let record: ApprovalRecord
    let date: Date
    let busy: Bool
    let revoke: () -> Void
    let details: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "bolt.shield.fill").foregroundStyle(.blue)
                Text(clientDisplayName(record.request)).font(.headline)
                Spacer()
                StatusBadge(state: record.state(at: date))
            }
            Text("\(vaultDisplay(record.request.scope.vaults)) · \(record.request.scope.operations.joined(separator: ", "))")
                .font(.subheadline).foregroundStyle(.secondary)
            if record.state(at: date) == "confirming" {
                Text("Waiting for confirmation from your Mac.").font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Button("Details", action: details).font(.subheadline.weight(.medium))
                Spacer()
                Button("Revoke access", role: .destructive, action: revoke).font(.subheadline.weight(.semibold))
                    .disabled(busy || record.revokeRequested).accessibilityIdentifier("revokeSession")
            }
        }.padding(20).card()
    }
}

private struct HistoryRow: View {
    let record: ApprovalRecord
    let date: Date
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: record.decision == "approve" ? "checkmark" : "xmark")
                .font(.subheadline.weight(.bold)).foregroundStyle(record.decision == "approve" ? Color.blue : Color.secondary)
                .frame(width: 32, height: 32).background(Color(.tertiarySystemFill), in: Circle())
            VStack(alignment: .leading, spacing: 4) {
                Text(clientDisplayName(record.request)).font(.subheadline.weight(.semibold))
                Text(vaultDisplay(record.request.scope.vaults)).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 5) {
                Text(record.decision == "approve" ? "Approved" : "Denied").font(.caption.weight(.semibold))
                Text(record.decidedAt, style: .relative).font(.caption2).foregroundStyle(.secondary)
            }
            Image(systemName: "chevron.right").font(.caption2.weight(.bold)).foregroundStyle(.tertiary)
        }.padding(16).contentShape(Rectangle())
    }
}

struct AccessDetails: View {
    let request: SessionRequest
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text(clientDisplayName(request)).font(.title2.bold())
            IntentDetails(request: request)
            ClientDetails(client: request.client, fallbackAgent: request.agent, fallbackHost: request.host)
            ScopeDetails(scope: request.scope)
            detail("Mac", request.host)
            detail("Duration", duration(request.durationSeconds))
            detail("Idle limit", duration(request.idleTimeoutSeconds))
        }
    }
}

private struct IntentDetails: View {
    let request: SessionRequest
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Approval intent").font(.subheadline.weight(.semibold))
            if let task = request.intent?.task, !task.isEmpty {
                detail("Task", task)
            }
            detail("Reason", request.intent?.reason ?? request.reason)
        }
    }
}

private struct ClientDetails: View {
    let client: ClientMetadata?
    let fallbackAgent: String
    let fallbackHost: String
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Client metadata").font(.subheadline.weight(.semibold))
            detail("Client", client?.displayName ?? fallbackAgent)
            if let client {
                detail("Name", client.clientName)
                detail("Version", client.productVersion)
                if let sessionName = client.sessionName, !sessionName.isEmpty { detail("Session", sessionName) }
                if let project = client.project, !project.isEmpty { detail("Project", project) }
                detail("Transport", client.transport)
                if !client.capabilities.isEmpty { detail("Features", client.capabilities.joined(separator: ", ")) }
            } else {
                detail("Host", fallbackHost)
            }
        }
    }
}

private struct ScopeDetails: View {
    let scope: SessionScope
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            detail("Account", scope.accounts.joined(separator: ", "))
            detail("Vaults", vaultDisplay(scope.vaults))
            detail("Items", scope.items.displayValue)
            detail("Allows", scope.operations.map { $0.capitalized }.joined(separator: ", "))
        }
    }
}

private struct StatusBadge: View {
    let state: String
    var body: some View {
        Text(state == "confirming" ? "Confirming" : state == "revoking" ? "Revoking" : state.capitalized)
            .font(.caption.weight(.semibold)).foregroundStyle(state == "active" ? Color.green : Color.secondary)
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(state == "active" ? Color.green.opacity(0.1) : Color(.tertiarySystemFill), in: Capsule())
    }
}

private func detail(_ label: String, _ value: String) -> some View {
    HStack(alignment: .top, spacing: 16) {
        Text(label).font(.subheadline).foregroundStyle(.secondary).frame(width: 70, alignment: .leading)
        Text(value).font(.subheadline.weight(.medium)).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
    }
}

private func clientDisplayName(_ request: SessionRequest) -> String {
    request.client?.displayName ?? request.agent
}

private func clientSubtitle(_ request: SessionRequest) -> String {
    if let client = request.client {
        let version = client.productVersion == "unknown" ? "" : " \(client.productVersion)"
        if let session = client.sessionName, !session.isEmpty { return "\(session) · \(request.host)\(version)" }
        return "\(request.host)\(version)"
    }
    return request.host
}

private func vaultDisplay(_ vaults: [String]) -> String {
    vaults.contains("*") ? "All allowed vaults" : vaults.joined(separator: ", ")
}

private func sectionTitle(_ title: String, count: Int) -> some View {
    HStack {
        Text(title).font(.headline)
        if count > 0 { Text("\(count)").font(.caption.weight(.semibold)).foregroundStyle(.secondary).padding(.horizontal, 8).padding(.vertical, 3).background(Color(.tertiarySystemFill), in: Capsule()) }
    }
}

private func duration(_ seconds: Int) -> String { seconds < 60 ? "\(seconds) sec" : "\(seconds / 60) min" }

private extension View {
    func card() -> some View {
        background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 22))
    }
}
