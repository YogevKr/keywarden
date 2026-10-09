import UIKit
import UserNotifications
import UserNotificationsUI

final class NotificationViewController: UIViewController, UNNotificationContentExtension {
    private let stack = UIStackView()
    private let scroll = UIScrollView()
    private var loadTask: Task<Void, Never>?
    private var expiryTask: Task<Void, Never>?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .secondarySystemGroupedBackground
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll)
        scroll.addSubview(stack)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: view.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -20),
            stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -20),
            stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -40)
        ])
        showMessage("Checking request", "Unlock your iPhone to view verified details.")
    }

    func didReceive(_ notification: UNNotification) {
        loadViewIfNeeded()
        loadTask?.cancel()
        expiryTask?.cancel()
        showMessage("Checking request", "Loading verified details…")
        loadTask = Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                guard let id = notification.request.content.userInfo["requestId"] as? String,
                      let context = try NotificationPreviewStore().load() else {
                    self.showMessage("Open Keywarden once", "Open the updated app to prepare request previews.")
                    return
                }
                let request = try await NotificationPreviewLoader().request(id, context: context)
                try Task.checkCancellation()
                // Recheck protected storage before displaying data after a network wait.
                guard let current = try NotificationPreviewStore().load(),
                      current.settings.brokerID == context.settings.brokerID,
                      current.settings.phoneID == context.settings.phoneID,
                      current.settings.brokerSigningPublicJWK == context.settings.brokerSigningPublicJWK,
                      !current.completedRequestIDs.contains(id) else { throw KeywardenError.requestExpired }
                self.show(request)
            } catch is CancellationError { return }
              catch KeywardenError.requestExpired {
                self.showMessage("Request unavailable", "This request expired or already has a decision. Open Keywarden for its status.")
            } catch KeywardenError.keychain {
                self.showMessage("Unlock to view details", "Unlock your iPhone, then expand this notification again.")
            } catch {
                self.showMessage("Details unavailable", "Open More details to check this request. No access has been granted.")
            }
        }
    }

    func didReceive(_ response: UNNotificationResponse, completionHandler completion: @escaping (UNNotificationContentExtensionResponseOption) -> Void) {
        completion(.dismissAndForwardAction)
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        loadTask?.cancel()
        expiryTask?.cancel()
        clear()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        resize()
    }

    private func clear() {
        for view in stack.arrangedSubviews { stack.removeArrangedSubview(view); view.removeFromSuperview() }
    }

    private func label(_ text: String, style: UIFont.TextStyle, color: UIColor = .label) -> UILabel {
        let label = UILabel()
        label.text = text
        label.font = .preferredFont(forTextStyle: style)
        label.adjustsFontForContentSizeCategory = true
        label.textColor = color
        label.numberOfLines = 0
        return label
    }

    private func showMessage(_ title: String, _ message: String) {
        clear()
        stack.addArrangedSubview(label(title, style: .headline))
        stack.addArrangedSubview(label(message, style: .subheadline, color: .secondaryLabel))
        resize()
    }

    private func show(_ request: SessionRequest) {
        clear()
        stack.addArrangedSubview(label(request.client?.displayName ?? request.agent, style: .title2))
        let session = request.client?.sessionName
        stack.addArrangedSubview(label(session.map { "\($0) · \(request.host)" } ?? request.host, style: .subheadline, color: .secondaryLabel))
        row("Account", request.scope.accounts.joined(separator: ", "))
        row("Vaults", request.scope.vaults.contains("*") ? "All allowed vaults" : request.scope.vaults.joined(separator: ", "))
        row("Items", request.scope.items.displayValue)
        row("Allows", request.scope.operations.map { $0.capitalized }.joined(separator: ", "))
        row("Duration", "\(request.durationSeconds / 60) min · Idle limit: \(request.idleTimeoutSeconds / 60) min")
        row("Reason", request.intent?.reason ?? request.reason)
        stack.addArrangedSubview(label("Approve or Reject opens Face ID confirmation. More details opens the full request.", style: .footnote, color: .secondaryLabel))
        resize()
        let delay = max(0, (parseDate(request.expiresAt) ?? .distantPast).timeIntervalSinceNow)
        expiryTask = Task { @MainActor [weak self] in
            do { try await Task.sleep(for: .seconds(delay)) } catch { return }
            self?.showMessage("Request expired", "Ask the agent to send a new request.")
        }
    }

    private func row(_ title: String, _ value: String) {
        let group = UIStackView()
        group.axis = .vertical
        group.spacing = 2
        group.addArrangedSubview(label(title, style: .caption1, color: .secondaryLabel))
        group.addArrangedSubview(label(value, style: .subheadline))
        stack.addArrangedSubview(group)
    }

    private func resize() {
        guard isViewLoaded, view.bounds.width > 0 else { return }
        let size = stack.systemLayoutSizeFitting(CGSize(width: view.bounds.width - 40, height: 0), withHorizontalFittingPriority: .required, verticalFittingPriority: .fittingSizeLevel)
        let target = CGSize(width: view.bounds.width, height: min(size.height + 40, 480))
        if preferredContentSize != target { preferredContentSize = target }
    }
}
