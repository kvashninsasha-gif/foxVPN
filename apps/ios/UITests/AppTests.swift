import XCTest

final class AppTests: XCTestCase {
    func testInvalidImportIsVisibleAndKeepsSheetOpen() {
        let app = XCUIApplication(); app.launchArguments = ["--ui-testing", "--ui-dark"]; app.launch()
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
    func testNormalLaunchLoadsRealKeychainWithoutTestMode() {
        let app = XCUIApplication(); app.launch()
        XCTAssertTrue(app.staticTexts["Отключено"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.alerts.firstMatch.exists)
    }
    func testEditingAndBackupWarning() {
        let app = XCUIApplication(); app.launchArguments = ["--ui-testing"]; app.launch()
        XCTAssertTrue(app.staticTexts["Отключено"].waitForExistence(timeout: 10))
        app.buttons["connectButton"].tap()
        let input = app.textViews["importText"]; XCTAssertTrue(input.waitForExistence(timeout: 5)); input.tap()
        input.typeText("vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=tcp#PublicFixture")
        app.buttons["Импортировать ссылки"].tap()
        app.tabBars.buttons["Серверы"].tap()
        let server = app.staticTexts["PublicFixture"]; XCTAssertTrue(server.waitForExistence(timeout: 5)); server.press(forDuration: 1)
        app.buttons["Редактировать"].tap()
        let name = app.textFields["serverName"]; XCTAssertTrue(name.waitForExistence(timeout: 5)); name.tap()
        name.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: "PublicFixture".count) + "My fox server")
        app.buttons["Сохранить изменения"].tap()
        XCTAssertTrue(app.staticTexts["My fox server"].waitForExistence(timeout: 5))
        app.tabBars.buttons["Настройки"].tap()
        let export = app.buttons["Экспортировать резервную копию"]; app.swipeUp(); XCTAssertTrue(export.waitForExistence(timeout: 5)); export.tap()
        XCTAssertTrue(app.staticTexts["Экспорт содержит ключи доступа"].waitForExistence(timeout: 5))
        app.buttons["Отмена"].tap(); XCTAssertFalse(app.buttons["Выбрать место сохранения"].exists)
    }
    func testUnavailableCameraReturnsToImport() {
        let app = XCUIApplication(); app.launchArguments = ["--ui-testing"]; app.launch()
        XCTAssertTrue(app.staticTexts["Отключено"].waitForExistence(timeout: 10))
        app.buttons["connectButton"].tap(); app.buttons["Сканировать QR"].tap()
        XCTAssertTrue(app.alerts.firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Камера недоступна в симуляторе. Используйте вставку ссылки или импорт файла."].exists)
        app.alerts.buttons["Закрыть"].tap()
        XCTAssertTrue(app.textViews["importText"].waitForExistence(timeout: 5))
    }

}
