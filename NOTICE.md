# Сторонние компоненты

sing-box 1.14.3 — SagerNet, GPL-3.0-or-later. Официальные исходники включены в vendor/sing-box-1.14.3-source.tar.gz; лицензия в vendor/sing-box-LICENSE. Источник: https://github.com/SagerNet/sing-box/tree/v1.14.3.

foxVPN собирает 1.14.3-foxVPN.2 из этого архива с закреплёнными зависимостями vendor/core-patches/go.mod и go.sum, Go 1.26.9 и тегами with_utls,with_gvisor,with_clash_api. Воспроизводимая команда: scripts/build-core.py --work-dir <папка> --scan; macOS TUN добавляет --network и scripts/macos/privilege_drop.go. Это сборка foxVPN, исходный архив поставщика не изменён. Версия и SHA256 исходников, overlay и конечного бинарника — core/version.json и core/network-version.json. Команда для просмотра compile tags встроенного бинарника: core/sing-box version.

Приложение использует Tauri, Rust crates и npm-пакеты по их собственным лицензиям. Точный состав зависимостей зафиксирован в Cargo.lock и apps/desktop/package-lock.json. Реализация VLESS/Reality не копировалась в приложение; сетевой протокол выполняет sing-box.
