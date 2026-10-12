# Go binary advisory gate

`scripts/check-go-advisories.py` проверяет поток JSON от `govulncheck -mode=binary -format=json`; одного exit code scanner недостаточно. Поток должен содержать единственную корректную config (`v1.0.0`, govulncheck `v1.8.0`, official `https://vuln.go.dev` и timestamp, binary/symbol), непустой SBOM с root module и согласованной stdlib/go_version, определения advisory для каждого finding и корректные непустые traces. Одинаковый OSV может повторяться для нескольких modules — он дедуплицируется; конфликтующие повторения, malformed/trailing JSON, error/unknown events, неполные traces или отсутствующие SBOM/config дают отказ.

Все reported module/package/symbol findings остаются видимыми (`finding_count`, `finding_levels`, `symbol_advisories` для нерешённых ID). Поле `symbol_advisories` сохранено для совместимости, но включает также unresolved module/package findings. Новая запись не игнорируется только потому, что её trace не содержит функции; module-level advisory может не перечислять affected package. Binary scan не подтверждает вызов функции и не заменяет source reachability/физическую приёмку.

## Единственное датированное исключение

[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) сообщает, что OpenPGP в `golang.org/x/crypto` небезопасен и не поддерживается; affected imports включают основной package и шесть children, все symbols. Это реальная проблема пакета; наличие `golang.org/x/crypto` ради другого алгоритма не равно использованию OpenPGP. Первичный [OSV JSON](https://vuln.go.dev/ID/GO-2026-5932.json) проверен 11.10.2026.

Для текущего sing-box бинарный scanner формирует псевдо-совпадения `receiver="golang"`, `function="org/x/crypto/openpgp/.../*"`. Review действует только с 11.10.2026 по 31.12.2026, для неизменённой metadata `modified=2026-07-07T22:15:29Z`, OSV schema `1.3.1`, семи точных affected OpenPGP imports, `golang.org/x/crypto v0.57.0` и `go1.26.9`. В группе должен присутствовать этот точный псевдо-wildcard. Concrete `ReadMessage`, `Decrypt`, смешанный concrete+wildcard, иной receiver/path/function, новая metadata/version/toolchain и истёкший review не исключаются.

Дополнительно обязателен **парный полный production-граф** `go list -mod=readonly -tags with_utls,with_gvisor,with_clash_api -deps -json ./cmd/sing-box`, вычисленный root build script в той же source tree и с теми же GOTOOLCHAIN/GOOS/GOARCH/CGO. Plain список из двух markers не годится. Gate проверяет root package `.../cmd/sing-box`, точное равенство его `Deps` всем graph nodes, замыкание Imports/Deps с ImportMap, required production packages, module/version против SBOM, отсутствие Error/DepsErrors/Incomplete/duplicate records. OpenPGP либо любой child, включая vendored spelling, в графе запрещает исключение. Хэши raw report и graph фиксируются в assessment; генерация этих данных доверяется поддерживаемому build script, а не произвольному присланному JSON.

## Выполненные проверки

- `python3 scripts/test-go-advisories.py`: **18 passed**. Проверяются реальные имена функций, смешанный trace, package/vendored presence, неполный граф, scanner metadata, новые advisory/module findings, версия и срок review, malformed stream, конфликтующие/идентичные OSV повторения и CLI failure JSON. CRLF CLI-проверка подтверждает SHA256 настоящих file bytes без нормализации строк.
- Реальный `hardened-network-028/govulncheck.json` + `compiled-packages.json` принят как **passed с видимым reviewed GO-2026-5932**: 15 событий (1 module, 7 package, 7 pseudo-symbol), unresolved ID отсутствуют. Воспроизводимый снимок публичных доказательств сохранён в `/Volumes/Hard/foxVPN/work/go-advisory-gate-check-028/`. Report SHA256 `a7d36551307329e70320bd7014dec3465b550dac1f2fa5e189b18931fe50c56f`; graph SHA256 `0d1c4513a81f0bcdcb75bd67959203265d32393d1b575ccd149faf5868493397`.
- Реальный hardened proxy report без парного графа остаётся unresolved; отсутствие graph не активирует исключение.

```sh
python3 scripts/test-go-advisories.py
python3 scripts/check-go-advisories.py target/core-source/govulncheck.json \
  --compiled-packages target/core-source/compiled-packages.json
```

Raw reports/graphs и assessment необходимо сохранять вместе: хэш без исходных доказательств не позволяет воспроизвести review. `build-core.py` принадлежит основному build-пути: pinned GPL source SHA256, go.mod/go.sum overlay, Go toolchain, tags, final core binary hash и scan status фиксируются там. Положительная assessment не означает «все зависимости безопасны» и не является приёмкой TUN/WFP/сна/аварий на устройствах.
