# Сторонние компоненты

sing-box 1.14.2 — SagerNet, GPL-3.0-or-later. Официальные исходники включены в vendor/sing-box-1.14.2-source.tar.gz; лицензия в vendor/sing-box-LICENSE. Источник: https://github.com/SagerNet/sing-box/tree/v1.14.2.

Компонент поставляется отдельно от кода GUI; версия, хэши официального архива и бинарника — core/version.json. Исходники и параметры сборки из официального релиза сохранены в архиве поставщика. Команда для просмотра compile tags встроенного бинарника: core/sing-box version.

Приложение использует Tauri, Rust crates и npm-пакеты по их собственным лицензиям. Точный состав зависимостей зафиксирован в Cargo.lock и apps/desktop/package-lock.json. Реализация VLESS/Reality не копировалась в приложение; сетевой протокол выполняет sing-box.
