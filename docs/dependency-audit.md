# Dependency gate — подзадача 5.1

Добавлен отдельный `.github/workflows/dependency-audit.yml`: push/PR по lockfiles и политике, ручной запуск на native Mac и Windows runners. Он устанавливает `cargo-audit 0.22.2 --locked`, проверяет npm install без lifecycle scripts, выполняет policy-тесты и `scripts/audit-dependencies.py`. Existing Windows/macOS release workflows не заменяются; этот workflow не публикует релиз и не меняет установленное приложение. CI ещё должен быть выполнен на опубликованном checkout.

RustSec сканируется без OS/CPU/severity фильтров и `ignore`, с `--deny warnings`; unsound/unmaintained/notice остаются в raw отчёте. Код scanner 1 допускается только при наличии разобранных findings; далее собственная политика классифицирует каждый advisory. Npm audit включает devDependencies и production зависимости; его baseline сейчас пуст. Любая npm vulnerability требует исправления — `npm audit fix --force` автоматически не запускается.

Каждая Rust assessment в `dependency-audit-baseline.json` имеет точные advisory ID, package, version, kind, причину, первичный источник, дату review и срок не более 90 дней. **Нет blanket ignore.** Неизвестный advisory/version/kind, истёкшее обоснование, неполное target-покрытие, новый reachable affected пакет, scanner/API failure, inconsistency JSON или изменение manifest/lockfile во время проверки останавливают gate. Удалённое предупреждение также требует убрать неиспользуемую assessment вместо накопления вечных исключений.

`not_in_shipped_targets` каждый раз проверяется по `cargo tree --locked --workspace --target ... --edges normal,build` для Mac arm64, Intel Mac и Windows x64. Учитываются build dependencies/procedural macros; одного поиска имени в lockfile недостаточно. `unmaintained_transitive` предусмотрен только для индивидуально объяснённой записи с kind `unmaintained`; текущий baseline его не использует и не разрешает этим способом security/unsound findings.

Все три дерева вычисляются на обоих native hosts: это дополнительно учитывает условные зависимости build/proc-macro, которые исполняются на host, а не в target binary. Отчёт сохраняет `scanner_host`; локальное вычисление Windows target на Mac не выдаётся за native Windows-run. Windows npm вызывается через `node` и проверенный npm JS entrypoint без cmd.exe/shell-интерполяции.

## Две конкретные записи

| Advisory/package | Содержание | Проверенная применимость и решение |
| --- | --- | --- |
| [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html), glib 0.18.5 | Реальная unsoundness `VariantStrIter`; исправлено в >=0.20.0 | Есть в общем lockfile, но отсутствует во всех трёх production/build target trees. Linux reverse tree подтверждает цепь GTK/Tauri. Оставлен видимый `reviewed_exception`; не объявлен безопасным и не разрешён для Linux выпуска |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html), proc-macro-error 1.0.4 | Прекращённая поддержка; patched version отсутствует | В Linux GTK procedural macro chain (`glib-macros`/`gtk3-macros`), отсутствует во всех трёх production/build target trees. Это maintenance debt, а не заявление об отсутствии риска. Повторный review при новом reachable пакете/версии или Linux выпуске |

Обе assessment пересмотрены 11.10.2026 и истекают 31.12.2026. Первичные RustSec страницы проверены в этот день; причины не заменяют локальное вычисление target trees.

## Фактический локальный результат 11.10.2026

- Gate выполнен на Mac с текущими manifest/lockfiles: **passed с двумя рассмотренными исключениями**, npm 0 findings. Политика не выдаёт Rust результат за полностью чистый lockfile.
- Cargo.lock: 568 dependency packages, SHA256 `9b811272232805f22ef556141901be8b1159901f2149e21cee4648b85d3454a1`.
- RustSec: 1296 записей, database commit `7eebec69c352c7191b1f13eb95dd510eeca5d1de`, last updated `2026-10-09T10:12:02+02:00`; scanner `cargo-audit 0.22.2`.
- Npm package-lock SHA256 `056222f06cc0f27eab1f2b3ac26563dfbb897d082c2c6a176e4ed9f661c6e63d`; npm 11.19.0 сообщает total 190 dependencies, 39 prod/152 dev (категории npm пересекаются), known vulnerabilities 0.
- Десять policy-тестов прошли: известные записи остаются видимыми, reachable build dependency отклоняется, новая версия/advisory/kind не подавляется, срок review ограничен, blanket npm assessment и missing target отвергаются, удалённые записи требуют очистки, npm advisory/API failure и фильтрация/count inconsistency отклоняются; Windows npm entrypoint проверяется без shell. End-to-end отсутствие scanner удаляет прежний success/raw evidence, пишет failed report и сохраняет постороннюю локальную заметку.
- Raw отчёты, stderr, scanner versions, три дерева и их SHA256 сохранены в `/Volumes/Hard/foxVPN/work/dependency-audit-0.1.28/current/`; результат — `summary.json`. GitHub workflow сохраняет аналогичный evidence artifact даже при отказе gate.

```sh
python3 scripts/test-audit-dependencies.py
python3 scripts/audit-dependencies.py --report-dir target/dependency-audit
```

Gate проверяет известные advisory на момент запуска. Он не доказывает отсутствие неизвестных уязвимостей и не является анализом бинарника/reachability конкретной функции. Отсутствие package в target tree — применимость к текущей конфигурации сборки; новый feature, target или Linux выпуск требует повторной оценки.

## Native компоненты

Проверки pinned sing-box/Go source, build manifest, binary/source SHA256 и `govulncheck` — отдельный связанный gate в scripts ядра; Rust/npm scanner их не покрывает. Зафиксированный Rust crate `llama-cpp-sys-2` включает native C/C++ и не получает автоматический полноценный C/C++ vulnerability-анализ от RustSec. Для supplier/source acceptance нужны точный upstream revision и отдельный review native sources. Updater signing/Developer ID/Authenticode остаются этапом 5.2 и не закрываются этим отчётом.
