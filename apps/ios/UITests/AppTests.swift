import XCTest

final class AppTests: XCTestCase {
    func testInvalidImportIsVisibleAndKeepsSheetOpen() {
        let app = XCUIApplication(); app.launchArguments = ["--ui-testing", "-AppleInterfaceStyle", "Dark"]; app.launch()
        XCTAssertTrue(app.staticTexts["Отключено"].waitForExistence(timeout: 10))
        let screenshot = XCTAttachment(screenshot: app.screenshot()); screenshot.name = "foxVPN-Dark"; screenshot.lifetime = .keepAlways; add(screenshot)
        app.buttons["connectButton"].tap()
        let input = app.textViews["importText"]; XCTAssertTrue(input.waitForExistence(timeout: 5)); input.tap(); input.typeText("invalid-link")
        app.buttons["Импортировать ссылки"].tap()
        XCTAssertTrue(app.staticTexts["Нужна корректная VLESS-ссылка с UUID, адресом и портом."].waitForExistence(timeout: 5))
        XCTAssertTrue(app.textViews["importText"].exists)
    }

    func testImportRuleAndSimulatorConnectionGuard() {
        let app = XCUIApplication(); app.launchArguments = ["--ui-testing"]; app.launch()
        XCTAssertTrue(app.staticTexts["Отключено"].waitForExistence(timeout: 10))
        let overview = XCTAttachment(screenshot: app.screenshot()); overview.name = "foxVPN-Overview"; overview.lifetime = .keepAlways; add(overview)
        app.buttons["connectButton"].tap()
        let input = app.textViews["importText"]; XCTAssertTrue(input.waitForExistence(timeout: 5)); input.tap()
        input.typeText("vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=tcp#PublicFixture")
        app.buttons["Импортировать ссылки"].tap()
        XCTAssertTrue(app.staticTexts["PublicFixture"].waitForExistence(timeout: 5))
        app.buttons["connectButton"].tap()
        XCTAssertTrue(app.staticTexts["Симулятор проверяет интерфейс. Для системного VPN установите подписанное приложение на настоящий iPhone."].waitForExistence(timeout: 5))
        app.buttons["Понятно"].tap()
        XCTAssertTrue(app.staticTexts["Отключено"].exists)
        app.tabBars.buttons["Правила"].tap()
        let domain = app.textFields["ruleDomain"]; XCTAssertTrue(domain.waitForExistence(timeout: 5)); domain.tap(); domain.typeText("*.example.ru")
        app.buttons["Добавить правило"].tap()
        XCTAssertTrue(app.staticTexts["*.example.ru"].waitForExistence(timeout: 5))
        let routing = XCTAttachment(screenshot: app.screenshot()); routing.name = "foxVPN-Routing"; routing.lifetime = .keepAlways; add(routing)
    }
}
