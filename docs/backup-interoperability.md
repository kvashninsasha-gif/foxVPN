# Публичный Mac↔Windows backup — подзадача 6.2

`tests/fixtures/public-backup-v1.json` — полностью публичный профиль без пользовательских данных. Он использует reserved `example.com`/`example.org`/`2001:db8::/32`, публичные тестовые UUID, два сервера (TCP/WS, IPv6), Unicode, URI parameters, selected/favorite/group, subscription, ordered exact/wildcard/Unicode rules, все настройки и наблюдения. Эти адреса не проверяются сетью.

`tests/backup_interoperability.rs` проверяет реальный `Profile` JSON и `Vault::save/load` на отдельных временных каталогах и разных публичных ключах в обоих направлениях. Новый объект Vault читает destination profile; исходный ключ destination decrypt выполнить не может. Native CLI import запускается отдельным процессом. Проверка сравнивает весь сериализованный профиль, поэтому не ограничивается количеством серверов и не теряет наблюдения или настройки.

Путь совпадает с форматом GUI `file_actions::export_backup/import_backup`: pretty JSON, `user_files::read_selected`, serde `Profile`, validation и сохранение Vault. Native file dialogs, согласие пользователя, реальный Keychain/Credential Manager, запущенное приложение и физическая установка в этот rootless harness не входят. Перед импортом реального backup GUI требует отключённое соединение; испытания не обходят это условие. Mac flags `tun`/`kill_switch` сохраняются как данные при импорте Windows и не доказывают реализацию Windows TUN/WFP; отдельный connection-plan требует подходящий охват/согласие.

## Native обмен артефактами

```sh
cargo test --locked --features test-support --test backup_interoperability
cargo run --locked --features test-support --example backup-interoperability -- export target/public-backup
# На другой native OS после скачивания public-backup.json + manifest.json:
cargo run --locked --features test-support --example backup-interoperability -- import target/incoming-backup
```

Export сначала сохраняет fixture в encrypted Vault и читает его, затем пишет обычный backup + manifest source OS/architecture/version/SHA256. Import проверяет версию, fixture identity, byte hash и все поля; сохраняет в destination encrypted Vault и читает новым Vault. При same-OS artifact, другой версии, неверном хэше/профиле success-report отсутствует. В manifest OS указана программой; доказательством native OS служит именно CI runner provenance, а не неподписанная строка в JSON.

Для полного обмена нужны четыре job в одном workflow: Mac export и Windows export (параллельно), Mac import Windows artifact и Windows import Mac artifact (после обеих export). Использовать `actions/upload-artifact@v4`/`download-artifact@v4`, уникальные имена с native OS, `if-no-files-found: error` и одинаковый checkout SHA. Отчёты `import-macos.json`/`import-windows.json` привязывают результат к source hash и version; входящий artifact следует загрузить отдельным шагом и получить отчёт только после native gate. Не использовать `continue-on-error` и не подменять чужой artifact локальным export. Rootless test использует feature `test-support`; пользовательская сборка не получает fixture-ключи в production Vault.

CRLF поддержан и проверяется вместе с Unicode. UTF-8 BOM соответствует существующему поведению GUI: serde reject; harness не обещает поддержку произвольных сторонних backup. Некорректная версия, missing selected ID, invalid DNS и duplicate server ID отклоняются до замены destination profile.

## Выполнено локально 11.10.2026

- `cargo test --locked --features test-support --test backup_interoperability`: 3 passed / 0 failed, реальная encryption/save/load в временных каталогах на Mac.
- Native example собран; `export` выполнен на Mac. SHA256 публичного JSON: `29c281d4d0304a3fdf2796e5097d38ef56e839e61e50f6d8134feafed8bbe75a`.
- CLI rejects: same-OS source, wrong engine version, byte-hash tamper, altered profile с пересчитанным SHA256. Все четыре отвергнуты; stale success-report удалён до проверки.

Публичные локальные artifacts находятся вне checkout в `/Volumes/Hard/foxVPN/work/backup-local-0.1.28`. Фактические результаты native CI фиксируются отдельно в итоговом отчёте выпуска. Подготовка harness и локальный обмен между двумя Vault на одном Mac **не закрывают** критерий «реальный перенос Mac↔Windows». OS credential dialogs и ручной импорт на устройствах остаются отдельными доказательствами.
