# foxVPN для iPhone · 0.1.1

Нативное приложение SwiftUI и настоящий `NEPacketTunnelProvider` с sing-box Libbox 1.14.2. Это предварительная версия: обе платформы собираются, интерфейс и конфигурации проверяются автоматически. Системная VPN-приёмка на физическом iPhone пока не выполнена.

## Что сделано

- Бренд foxVPN, логотип лисы на щите, русские экраны, системная светлая/тёмная тема.
- VLESS TCP/WS/gRPC, TLS и Reality, строгая проверка UUID/ключей/параметров и исключение дублей.
- Импорт текста, файла профиля desktop, QR через камеру; QR и передача ссылки выбранного сервера. Замена существующего JSON-профиля требует подтверждения.
- Выбор серверов, редактирование имени и группы, избранное, поиск, удаление с подтверждением.
- Экспорт JSON-профиля в выбранное место через «Файлы», с предупреждением о ключах; обратный импорт на Mac.
- Изменение порядка правил; удаление подписки с выбором сохранить либо удалить её серверы.
- Четыре режима; доменные исключения, IDN, `*.` только для поддоменов; проверка правила без сетевого запроса.
- DoH/DoT Cloudflare/Google/Quad9 и системный DNS через публичный DNS-SD API, привязанный к физическому интерфейсу.
- HTTPS-подписки с ручным обновлением, обычный и URL-safe Base64; ограничение 4 MB, атомарная замена, сохранение старого списка при ошибке.
- Системное подключение/отключение, политика `includeAllNetworks`, подключение по требованию. Настройки активного туннеля заблокированы; явное отключение отменяет On Demand до следующего подключения.
- Проверка HTTPS-доступности после системного подключения, счётчики реального ядра через сообщения расширения.
- Весь профиль в общем Keychain приложения и расширения, без iCloud-синхронизации; `AfterFirstUnlockThisDeviceOnly`. Отказ доступа не затирает сохранённые данные.

## Установка на iPhone

Обычного Apple ID / Personal Team недостаточно для подписи собственного Network Extension. Нужна команда Apple Developer Program с доступом к Network Extensions, App Groups и Keychain Sharing. Это ограничение Apple, а не дополнительный пароль приложения. См. [разъяснение Apple DTS](https://developer.apple.com/forums/thread/128767) и [таблицу возможностей iOS](https://developer.apple.com/help/account/reference/supported-capabilities-ios).

1. Откройте `foxVPN.xcodeproj` в Xcode.
2. Для приложения **foxVPN** и расширения **FoxVPNTunnel** выберите одну доступную команду в Signing & Capabilities. Не сохраняйте Team ID и сертификаты в публичный репозиторий.
3. Идентификаторы `ru.smartvpn.router.ios`, `.tunnel` и `group.ru.smartvpn.router.ios` должны быть доступны вашей команде. При конфликте задайте свой префикс в `project.yml`, включая `FOX_KEYCHAIN_GROUP`, затем выполните `xcodegen generate`.
4. Подключите разблокированный iPhone, подтвердите доверие и Developer Mode в системных настройках, выберите схему foxVPN и Run.
5. Импортируйте свою VLESS-ссылку либо экспорт JSON из foxVPN на Mac. Первый Connect вызывает системное разрешение добавления VPN-конфигурации; подтвердите его самостоятельно.
6. Выполните физическую приёмку из `verification-0.1.1.md`. Удалять другие VPN-клиенты для сборки приложения не требуется.

Архив **DevelopmentKit** содержит проект, исходники и готовый arm64 Libbox. **Simulator** работает только в iOS Simulator на Apple Silicon. **Unsigned-iPhone** — результат компиляции для устройства, а не устанавливаемая IPA. Без корректной подписи/provisioning установка на телефон не выполнится.

## Сборка из Git

Нужны macOS, Xcode с iOS SDK, XcodeGen 2.46+ и Go 1.25.5+. Проверено Xcode 27.0, iOS SDK 27.0, Apple Silicon; минимальная цель приложения iOS 16.0. Intel Simulator пока не включён.

```sh
# Из корня репозитория. Framework не хранится в Git: он есть в DevelopmentKit
# либо собирается из включённого закреплённого архива исходников.
python3 apps/ios/scripts/build-core.py --work-dir /tmp/foxvpn-ios-core --go /usr/local/go/bin/go
cd apps/ios
xcodegen generate
swift test --scratch-path /tmp/foxvpn-swift-tests
xcodebuild -project foxVPN.xcodeproj -scheme foxVPN -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' build
xcodebuild -project foxVPN.xcodeproj -scheme foxVPN -sdk iphoneos -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
# Для UI/engine тестов подставьте имя существующего симулятора из xcrun simctl list.
xcodebuild -project foxVPN.xcodeproj -scheme foxVPN -destination 'platform=iOS Simulator,name=iPhone 18 Pro' test
```

Для симулятора проект использует локальную ad-hoc подпись `-`. Она нужна для настоящего доступа к Keychain и не требует сертификата Apple Developer. Не отключайте подпись в simulator test: без неё SecItem API отклоняет доступ. Подпись для iPhone и публикации настраивается отдельно.

`build-core.py` проверяет SHA256 `vendor/sing-box-1.14.2-source.tar.gz`, использует SagerNet gomobile/gobind v0.1.12 и создаёт device arm64 + simulator arm64 с gVisor/uTLS/QUIC/Clash API и low-memory. `Frameworks/Libbox.xcframework` игнорируется Git. Go-модули закреплены upstream `go.mod`/`go.sum`; первая сборка требует сети. Полные исходники используемого ядра и лицензия доступны в `vendor/`. GPL-3.0 — как у desktop; сведения upstream: [sing-box](https://github.com/SagerNet/sing-box).

## Совместимость и ограничения

JSON, экспортированный iOS, также проверен десериализацией и валидацией настоящим Rust-движком desktop. Экспорт desktop JSON v1 читается с сохранением серверов, выбора, правил и подписок. Параметры macOS helper/TUN/PF не переносятся: iOS использует собственные Network Extension и On Demand. JSON/QR/Share Link содержат ключи сервера; это явный экспорт пользователя.

Системный статус и HTTPS-проверка показываются отдельно: до успешного HTTPS приложение пишет «Проверяем связь». HTTPS-проверка подтверждает доступность интернета, но сама по себе не доказывает адрес выхода, отсутствие DNS/IPv6-утечек или правильность всех исключений. Политика iOS `includeAllNetworks` не равна проверенному macOS PF Kill Switch; её поведение при сбое ядра ещё предстоит проверить на телефоне.

Libbox ограничен 40 MiB и использует low-memory сборку; фактическое потребление и поведение при нехватке памяти на iPhone не измерены. Runtime-каталог App Group защищён File Protection, доступом 0700 и исключён из резервной копии. Снимок `configuration.json`, создаваемый ядром при старте, удаляется после успешного запуска; при аварии в момент старта он может временно остаться в защищённом контейнере. Диагностические crash-файлы ядра могут содержать данные конфигурации: приложение их никуда не отправляет. Не публикуйте контейнер и системные журналы.

Нет синхронизации с Mac, автоматического перебора серверов, измерения скорости/задержки каждого сервера, фонового обновления подписок, локального HTTP API macOS и установки из App Store/TestFlight. Камера, физический VPN, смена Wi-Fi/сотовой сети, энергопотребление, утечки и восстановление после перезагрузки ожидают физической приёмки. Старые показатели desktop сервера в iOS не выдаются за свежие измерения.

У приложения нет рекламы/аналитики. Сеть используется для VPN, выбранных DNS, заданных пользователем подписок и HTTPS-проверки состояния подключения `www.gstatic.com/generate_204`. App Store privacy manifest, экспортная классификация и проверка публикационных требований должны быть завершены перед отдельной публикацией в App Store; этот релиз — комплект разработки и unsigned-сборки.

Отчёт: [проверки 0.1.1](verification-0.1.1.md). Установка, TestFlight и App Store: [пошаговая инструкция](publication.md).
