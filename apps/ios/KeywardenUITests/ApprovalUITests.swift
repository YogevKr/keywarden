import XCTest

final class ApprovalUITests: XCTestCase {
    func testNotificationApproveAndRejectReachBiometricConfirmation() {
        for (action, reason) in [("Approve", "Approve access for Codex"), ("Reject", "Deny this access request")] {
            let app = XCUIApplication()
            app.launchArguments = ["--ui-fixture", "--notification-preview-fixture"]
            app.launch()
            let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
            let allow = springboard.buttons["Allow"]
            if allow.waitForExistence(timeout: 2) { allow.tap() }
            XCTAssertTrue(app.buttons["approveRequest"].waitForExistence(timeout: 5))
            XCUIDevice.shared.press(.home)
            let notification = springboard.staticTexts["Approval requested"].firstMatch
            XCTAssertTrue(notification.waitForExistence(timeout: 15))
            notification.press(forDuration: 1.5)
            XCTAssertTrue(springboard.buttons[action].waitForExistence(timeout: 5))
            springboard.buttons[action].tap()
            XCTAssertTrue(app.navigationBars["Approval details"].waitForExistence(timeout: 8))
            let expected = "Could not send your decision. Notification test: \(reason)"
            XCTAssertTrue(app.staticTexts[expected].waitForExistence(timeout: 5))
            capture("Notification \(action) confirmation")
            app.terminate()
        }
    }

    func testExpandedNotificationShowsVerifiedScopeAndOpensExactRequest() {
        let app = XCUIApplication()
        app.launchArguments = ["--ui-fixture", "--notification-preview-fixture"]
        app.launch()
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let allow = springboard.buttons["Allow"]
        if allow.waitForExistence(timeout: 3) { allow.tap() }
        XCTAssertTrue(app.buttons["approveRequest"].waitForExistence(timeout: 5))
        XCUIDevice.shared.press(.home)
        let notification = springboard.staticTexts["Approval requested"].firstMatch
        XCTAssertTrue(notification.waitForExistence(timeout: 15))
        notification.press(forDuration: 1.5)
        XCTAssertTrue(springboard.staticTexts["Account"].waitForExistence(timeout: 8))
        XCTAssertTrue(springboard.staticTexts["agents"].exists)
        XCTAssertTrue(springboard.buttons["Approve"].exists)
        XCTAssertTrue(springboard.buttons["Reject"].exists)
        XCTAssertTrue(springboard.buttons["More details"].exists)
        capture("Expanded notification")
        springboard.buttons["More details"].tap()
        XCTAssertTrue(app.navigationBars["Approval details"].waitForExistence(timeout: 8))
        capture("Notification request details")
    }

    func testPendingRequestHistoryAndSettings() {
        let app = XCUIApplication()
        app.launchArguments = ["--ui-fixture"]
        app.launch()
        XCTAssertTrue(app.buttons["approveRequest"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Needs approval"].exists)
        XCTAssertFalse(app.textFields["Relay URL"].exists)
        capture("Pending approval")
        app.swipeUp()
        XCTAssertTrue(app.staticTexts["History"].waitForExistence(timeout: 3))
        XCTAssertTrue(app.staticTexts["Approved"].exists)
        XCTAssertTrue(app.staticTexts["Denied"].exists)
        capture("Approval history")
        app.buttons["settingsButton"].tap()
        XCTAssertTrue(app.buttons["scanSetupQR"].waitForExistence(timeout: 3))
        XCTAssertFalse(app.textFields["Relay URL"].exists)
        capture("Settings")
        app.swipeUp()
        app.buttons["advancedConnection"].tap()
        XCTAssertTrue(app.textFields["Relay URL"].waitForExistence(timeout: 3))
        app.navigationBars["Advanced connection"].buttons.element(boundBy: 0).tap()
        app.buttons["Done"].tap()
        XCTAssertTrue(app.buttons["settingsButton"].waitForExistence(timeout: 3))
    }

    func testEmptyStateKeepsHistoryVisible() {
        let app = XCUIApplication()
        app.launchArguments = ["--ui-fixture", "--empty"]
        app.launch()
        XCTAssertTrue(app.staticTexts["No pending requests"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["History"].exists)
        XCTAssertFalse(app.buttons["approveRequest"].exists)
        capture("No pending requests")
    }

    func testNotificationSettingsMatchPermission() {
        for (argument, title, canEnable) in [
            ("--notifications-enabled", "Enabled", false),
            ("--notifications-new", "Not enabled", true),
            ("--notifications-denied", "Disabled", false),
            ("--notifications-quiet", "Delivered quietly", false),
            ("--notifications-alerts-off", "Alerts off", false)
        ] {
            let app = XCUIApplication()
            app.launchArguments = ["--ui-fixture", argument]
            app.launch()
            app.buttons["settingsButton"].tap()
            let permission = app.descendants(matching: .any)["notificationPermission"].firstMatch
            XCTAssertTrue(permission.waitForExistence(timeout: 3))
            XCTAssertEqual(permission.value as? String, title)
            XCTAssertEqual(app.buttons["enableNotifications"].exists, canEnable)
            XCTAssertEqual(app.buttons["openNotificationSettings"].exists, !canEnable)
            XCTAssertTrue(app.staticTexts["Mac paired"].exists)
            XCTAssertFalse(app.staticTexts["Phone connected"].exists)
            capture("Settings \(title)")
            app.terminate()
        }
    }

    func testSettingsSupportLargeTextAndConnectionReplacementConfirmation() {
        let app = XCUIApplication()
        app.launchArguments = ["--ui-fixture", "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"]
        app.launch()
        app.buttons["settingsButton"].tap()
        XCTAssertTrue(app.buttons["scanSetupQR"].waitForExistence(timeout: 3))
        capture("Settings large text")
        app.buttons["scanSetupQR"].tap()
        XCTAssertTrue(app.buttons["Scan new setup QR"].waitForExistence(timeout: 3))
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.staticTexts["Mac paired"].exists)
    }

    func testAdvancedEditsDoNotChangeConnectionUntilSaved() {
        let app = XCUIApplication()
        app.launchArguments = ["--ui-fixture"]
        app.launch()
        app.buttons["settingsButton"].tap()
        app.swipeUp()
        app.buttons["advancedConnection"].tap()
        let field = app.textFields["Broker ID"]
        XCTAssertTrue(field.waitForExistence(timeout: 3))
        field.tap()
        field.typeText("-unsaved")
        app.navigationBars["Advanced connection"].buttons.element(boundBy: 0).tap()
        app.buttons["advancedConnection"].tap()
        XCTAssertEqual(app.textFields["Broker ID"].value as? String, "broker_fixture")
    }

    private func capture(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
