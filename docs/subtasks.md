# Подзадачи плана foxVPN

Актуально на 12.10.2026. Работа ведётся по зависимостям. «Готово» означает указанные доказательства; физические испытания/сертификаты учитываются отдельно. Исходный план: [readiness-plan.md](readiness-plan.md).

| ID | Подзадача | Зависит от | Критерий | Статус |
| --- | --- | --- | --- | --- |
| 1.1–1.5 | Актуальность профиля, наблюдения, diff правил, scope, сеанс/отмена | — | Регрессии, core/Vault, native CI и подписанные релизы | Готово в 0.1.27 в объёме отчёта |
| 2.1 | Защищённый журнал незавершённой настройки | — | AES-GCM с отдельным контекстом, private atomic/fsync; подмена/сбой IO отвергаются | Реализовано 0.1.28; шифрование/права/IO/lease локально проверены |
| 2.2 | Checkpoint до каждого изменяющего шага и безопасное завершение | 2.1 | Stop/save/start/verify/rollback ошибки не теряют before; проверка отмены и crash | Реализовано 0.1.28; checkpoint/отмена/чужой и исчезнувший журнал проверены |
| 2.3 | Восстановление после перезапуска с согласием и без потери поздних правок | 2.1–2.2 | Startup не подключает VPN поверх pending; stale profile защищён; UI restore/discard | Реализовано 0.1.28; поздний disk profile и UI согласие проверены |
| 2.4 | Испытания аварий в отдельных процессах | 2.1–2.3 | Завершение до/после save/start/verify; новые процессы читают реальный encrypted журнал | Локальные child-process crash/FIFO/lock испытания пройдены; системная матрица отдельно |
| 2.5 | Контролируемый возврат Mac GUI после неудачного запуска | — | Только проверенная предыдущая app; atomic exchange, readiness, нет цикла; floor helper не ослаблен | Реализовано; 12 native rollback + 5 App paint tests; переход из 0.1.28, устройство не принято |
| 2.6 | Восстановление Windows GUI после неудачного обновления | — | Проверенный предыдущий installer/backup, профиль цел, consent, restart/отмена | Частично: original-key cache + readiness/repair guidance; автоматический откат не реализован |
| 3.1 | Автоматизированный протокол физической VPN-матрицы | — | Сценарии/ожидания IPv4/IPv6/DNS/UDP/QUIC/rules/failover/sleep/reboot | Готов протокол 22 сценариев + 10 policy tests; физические результаты не подставлялись |
| 3.2 | Выполнить матрицу на Mac после установки конечной версии | 2,3.1 | Фактические результаты и восстановление сети | Требуется согласованное окно прерывания VPN |
| 3.3 | Приёмка Windows на личном ПК | 2,3.1 | Installer/proxy/updater/browser/reboot | Отложено пользователем |
| 4.1 | Схема Windows service/IPC/установки и модель прав | — | Owner/process authentication, ограниченные команды/пути, upgrade/remove | Service/IPC/ACL/installer готовы в своей области; ordinary-owner native CI 38218201158 пройден, Start отключён |
| 4.2 | Реализация service и TUN/DNS/маршрутов | 4.1 | Подключение/stop без proxy, privilege boundaries, восстановление | Открыто: owned TUN/DNS/маршруты не реализованы; Wintun provenance закреплён |
| 4.3 | WFP Kill Switch и матрица сбоев | 4.2 | IPv4/IPv6/UDP/DNS/boot/crash без утечек | Открыто: upstream dynamic WFP не заменяет persistent Kill Switch |
| 4.4 | Native Windows service/TUN/WFP испытания и выпуск | 4.1–4.3 | Привилегированный disposable runner + устройство | IPC/upgrade/restart/remove runner пройден; TUN/WFP/device приёмка открыта |
| 5.1 | Dependency-аудит в CI с оценкой платформ и vendor-core | — | Rust/npm и pinned native components; не скрывать все advisory | Rust/npm + Go gates пройдены Mac/Windows; исключения точные/датированные/видимые; C/C++ отдельно |
| 5.2 | Подпись Developer ID/нотарификация и Authenticode | — | Проверенные сертификаты/конечные файлы | Доступных Developer ID/Apple signing identities не обнаружено; Authenticode не предоставлен |
| 6.1 | Intel Mac build и проверка без обещания приёмки | — | x86_64 app/helper/core и подпись/update channel | Запланировано |
| 6.2 | Реальный перенос публичного backup Mac↔Windows | — | Сохранность серверов/rules/subscriptions/settings | Пройден reciprocal native public JSON/Vault перенос Mac↔Windows; OS keyring/GUI физически отдельно |
| 6.3 | iPhone signing/provisioning и физическая матрица | — | Network Extension/App Groups/Keychain и устройство | Внешняя подпись/устройство, не подтверждены |
| 7.1 | Мгновенная скорость/история/качество измерений | — | Проверки счётчиков/перезапуска/ограничения хранения | Запланировано |
| 7.2 | Upload/loss и UI ограничений трафика | — | Реальный endpoint, точный объём, timeout/cancel | Запланировано |
| 7.3 | GeoIP/GeoSite и правила приложений | — | Проверенные источники/версии/маршруты | Запланировано |
| 7.4 | Независимое обновление ядра/баз | 7.3 | Целостность, compatibility, consent, rollback | Запланировано |

После каждого проверенного desktop изменения выпускать новую неизменяемую версию по AGENTS.md. Последние 7.x — отдельные функции 1.1/1.2, не расширяют первоначальный MVP задним числом. Журналы/профили/ключи пользователя в GitHub не публиковать.
