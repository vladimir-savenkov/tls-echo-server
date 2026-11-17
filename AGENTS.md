# AGENTS.md — руководство для AI-агентов

## Обзор проекта

**tls-echo-server** — асинхронные TLS echo-сервер и клиент на C++17.
Сервер принимает TLS-соединения, читает бинарные пакеты и возвращает их
обратно (echo). Клиент открывает несколько одновременных TLS-соединений
и гоняет через них последовательности запрос/ответ в общем пуле потоков.

Документация и комментарии в коде пишутся на русском языке — поддерживайте
этот стиль при изменениях.

### Технологический стек

- C++17 (CMake ≥ 3.16, сборка Ninja или Make)
- Boost.Asio (асинхронный ввод-вывод), Boost.Program_options (CLI),
  Boost.Thread
- OpenSSL (TLS 1.2 и выше: negotiate до 1.3, пол 1.2, RFC 8996)
- spdlog (асинхронное журналирование: файл + цветной stdout)
- Python 3 (вспомогательные клиенты и проверки CI)
- Зависимости: системные пакеты Ubuntu (`libboost-all-dev`, `libssl-dev`,
  `libspdlog-dev`) либо vcpkg по манифесту `vcpkg.json`

## Сетевая архитектура и протокол

- Бинарный протокол: заголовок `PacketHeader` (ровно 14 байт,
  `#pragma pack(push, 1)`, проверяется `static_assert`) — `uint16 magic`
  (маркер `0x5445`, на проводе байты `'T','E'`), `uint8 version` (текущая 1),
  `uint8 flags` (бит `0x01` — пакет-уведомление об ошибке: код в `id`, пустой
  payload; остальные биты 0), `uint32 id`, `uint16 len`, `uint32 crc`, затем
  полезная нагрузка `len` байт. Неверный magic/версия/флаги и превышение
  лимита размера — протокольный отказ: сервер отправляет пакет-уведомление
  (коды: 1 — превышение лимита размера, 2 — протокольная ошибка) и закрывает
  соединение без эха; отвергнутый payload сливается порциями по 4 КБ, чтобы
  клиент дописал запрос и получил уведомление (при чужом magic — best-effort
  без слива); клиент обязан принять уведомление и отобразить причину.
  `Packet::deserialize` бросает `std::invalid_argument`.
- Многобайтовые поля заголовка передаются в сетевом порядке байт (переносимые функции `wire::to_network16/32` и `wire::from_network16/32`
  из `include/wire.h`; POSIX-заголовки не нужны).
- CRC32 (полином zlib `0xEDB88320`) считается по полезной нагрузке;
  максимальный размер пакета — 65535 байт (`uint16_t`).
- Сервер: `TlsServer` — один `io_context` на пуле потоков, акцептор и
  реестр сессий живут на `control_strand_`; у каждой сессии собственный
  strand для сокета и таймера, lifetime держится через `shared_from_this`. Корректное завершение по SIGINT/SIGTERM:
  акцептор закрывается, активным сессиям даётся 5 секунд (настраивается),
  затем их сокеты закрываются; цикл обрабатывает отменённые операции до выхода.
  Повторный сигнал — `force_stop()`: сокеты сессий закрываются немедленно;
  обработчик сигналов в main реармится после каждого сигнала.
  Не заменяйте это на `io_context_.stop()`: он оставляет обработчики в очереди.
- Клиент: `TlsClient` (resolve → connect → handshake) + `TlsConnection`
  (низкоуровневые async_write/read через strand) + `BasicClient<Connection>`
  — шаблонный класс логики запрос/ответ, параметризованный «соединением»
  с интерфейсом `async_write / async_read_exactly / close / abort`. Это позволяет
  тестировать логику на поддельных соединениях без сети. У `TlsConnection`
  раздельные дедлайны записи и чтения: при окне > 1 операции пересекаются,
  и общий таймер отменялся бы чужим `end()`.
- Обе стороны включают `TCP_NODELAY` (`boost::asio::ip::tcp::no_delay`):
  сервер — в конструкторе `Session`, клиент — в обработчике connect до
  TLS handshake. Иначе алгоритм Нагла придерживает хвостовые сегменты записи
  до ACK, и паузы delayed-ACK (до 40 мс на Linux, 200 мс на Windows) попадают
  в измеряемые p50/p95/p99.
- ID пакетов клиента: `100 + номер_пакета`; клиент проверяет CRC,
  ожидаемый ID и точное совпадение полезной нагрузки каждого ответа.
- `BasicClient` уведомляет о результате обмена один раз на последовательность;
  при ошибке вызывает `abort()`. `TlsClient` уведомляет один раз после ошибки
  либо завершения TLS shutdown. `exchange_complete()` и `succeeded()` различаются:
  последний требует успешного shutdown. Владельцы хранят сервер/клиентов до
  обработки всех операций; результаты клиента читаются на его strand или
  после завершения worker-потоков.
- `OperationDeadline` ограничивает DNS/connect/handshake/read/write/shutdown
  (по умолчанию 10000 мс на операцию). Отмена таймера повышает номер поколения,
  чтобы готовый callback старого таймера не отменил следующую операцию.
  Отменяйте таймеры через `cancel()` без аргумента: перегрузка с `error_code`
  удалена в новых версиях Boost. Для всех целей определён
  `BOOST_ASIO_NO_DEPRECATED`, чтобы ловить такие ошибки и на Linux.
- `ServerOptions`: максимум 1024 сессии, максимум 65535 байт данных,
  таймаут операции и срок drain. Размер отвергается до выделения буфера.
  `stats()` читает атомарные счётчики (принято/отклонено/ошибки accept/
  таймауты/превышения/протокольные ошибки/эхо-пакеты/эхо-байты/активно); согласованный итог
  получают после join. Счётчик эха инкрементируется сессией после успешной
  полной записи ответа.
- `ClientRunOptions`: размер бинарных данных, длительность и окно pipelining
  на соединение после handshake; в режиме длительности отправленные запросы
  дорабатываются до полных ответов до shutdown. `window` (1..1024, по
  умолчанию 8) — число запросов в полёте без ответа: pipelining действует
  только в режиме длительности (записи строго последовательны, одна цепочка
  чтения, ответы FIFO, задержка — от метки отправки своего запроса); счётный
  режим форсирует окно 1 — строгий ping-pong для честных измерений задержки.
  `LatencyStats` — ограниченная гистограмма (512 интервалов, 8 на удвоение),
  p50/p95/p99 являются верхними границами с погрешностью до 9.1% от 1 мкс.
  Задержка DNS+TCP+TLS измеряется отдельно от запроса.
- Журналирование: логгеры spdlog передаются как `std::shared_ptr` и
  внедряются в классы; на уровне `debug` логируются состояния всех
  асинхронных операций и данные пакетов (непечатные байты экранируются
  функцией `escape_log_payload` из `include/log_payload.h`). Очередь
  асинхронного логгера в main использует политику `overrun_oldest`
  (`create_async_nb`): сетевые потоки не блокируются на журналирование,
  при переполнении теряются старые debug/info; файл сбрасывается на
  `warn` и выше.

## Структура каталогов

- `include/` — заголовки: `protocol.h` (формат пакета, `Packet`,
  `calculate_crc32`), `server.h` (`TlsServer` + вложенный `Session`),
  `client.h` (`TlsConnection`, `TlsClient`), `basic_client.h`
  (`BasicClient<Connection>`, `ClientError`, `ClientRunOptions`),
  `log_payload.h`, `wire.h`, `operation_deadline.h`, `latency_stats.h`.
- `src/` — `main.cpp` (точка входа сервера), `server.cpp`, `main_client.cpp`
  (точка входа клиента), `client.cpp`, `protocol.cpp`.
- `tests/` — шесть самодостаточных тестов (без фреймворка, см. ниже).
- `fuzz/` — `fuzz_packet.cpp`, точка входа libFuzzer для парсера пакетов
  (см. «Фаззинг»).
- `scripts/` — `generate-certs.sh` (самоподписанный сертификат),
  `sanitizer_smoke.py` (прогон сервера и клиента под санитайзерами),
  `msan_packet_test.sh`, `fuzz_packet.sh` (сборка и прогон libFuzzer-цели),
  `coverage.sh`, `multi_client_test.py`,
  `interactive_client.py`, `bump-version.sh` (поднимает версию в
  `CMakeLists.txt` и `vcpkg.json`, коммитит и создаёт аннотированный тег;
  пуш — вручную).
- `CMakeLists.txt` — единственный файл сборки: библиотека `protocol`
  (`src/protocol.cpp`), статическая `tls_core` (сетевое ядро:
  `src/server.cpp` + `src/client.cpp`, общая для боевых бинарников и
  сквозного теста), исполняемые файлы `server` и `client`, шесть тестов.
- `CMakePresets.json` — пресеты vcpkg для Windows/Linux (Debug/Release),
  рабочий процесс Visual Studio «Open Folder».
- `.github/workflows/` — `ci.yml` (CI) и `release.yml` (публикация релизов).
- `.agents/skills/tls-echo-ci-triage/` — скилл для диагностики падений CI.
- Каталоги `client/` и `cmake/` пустые; `build/` — gitignored, содержит
  локальные сборки (в т.ч. `asan/`, `tsan/`, `msan/`, `coverage/`).
  В корне лежат `CMakeCache.txt` и `CMakeFiles/` — артефакты случайной
  сборки в исходниках; не воспроизводите это, собирайте из каталога `build/`.

## Сборка и запуск

Зависимости на Ubuntu:

```bash
sudo apt-get install build-essential clang cmake ninja-build openssl python3 \
  libboost-all-dev libssl-dev libspdlog-dev
```

Сборка и тесты из корня проекта:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

Release собирается в отдельный каталог (`build/release`). Бинарники:
`build/server`, `build/client`. Локальный прогон:

```bash
bash scripts/generate-certs.sh                    # создаёт server.crt/key
./build/server --cert server.crt --key server.key # порт 8443, 4 потока
./build/client --host localhost --port 8443 --cert server.crt --clients 100 --threads 4 --packets 20
```

Важные опции сервера: `--port` (по умолчанию 8443), `--threads`,
`--log-file` (по умолчанию `server.log`), `--log-level`, `--log-append`
(дописывать журнал вместо усечения при запуске; без флага файл усекается),
`--bind` (адрес привязки IPv4/IPv6; по умолчанию 0.0.0.0; IPv6-адрес
включает dual-stack — один сокет для обоих семейств; недоступный адрес —
ошибка запуска, без отката).
У клиента `--host` обязателен. Проверка TLS включена по умолчанию: `--cert` задаёт доверенный CA,
иначе используется хранилище OpenSSL; имя DNS/IP также проверяется, для DNS
передаётся SNI. Явный `--insecure` отключает проверку и несовместим с `--cert`.
На Windows OpenSSL не обязан использовать системное хранилище Windows.
Каждому проверяемому соединению передавайте отдельный TLS-контекст/trust store:
системная OpenSSL 3.0 может конкурентно менять ленивые X509-кеши общего store.
CLI создаёт контексты до начала измерения; многопоточный TLS-тест проверяет
сертификаты с отдельными контекстами. Не подавляйте такие отчёты TSan.

Новые опции сервера: `--max-connections` (1024), `--max-payload` (65535),
`--timeout-ms` (10000), `--shutdown-timeout-ms` (5000). Новые опции клиента:
`--timeout-ms` (10000), `--payload-size` (0..65535), `--duration` (секунды,
несовместим с явным `--packets`), `--window` (1..1024, окно pipelining;
действует только в режиме `--duration`, в счётном режиме принудительно 1),
`--resume` (session resumption, см. ниже).
Клиент выводит throughput, MiB/с полезных данных и квантили задержек.
Полный список — через `--help`.

TLS session resumption: сервер включает кеш сессий вызовом
`enable_tls_session_cache` (`src/server.cpp`) — session id context обязателен,
без него OpenSSL не кеширует; таймаут кеша 300 с, TLS 1.3 ticket-ключ
эфемерный (resumption живёт в пределах процесса, рестарт всё инвалидирует).
Клиентский `--resume`: первое соединение («primer») проходит полный handshake,
после обмена его сессия захватывается (`TlsClient::session()`,
`SSL_get1_session`) и передаётся остальным соединениям через
`TlsClientOptions::resume_session` (`SSL_set_session` до handshake). TLS 1.3
шлёт ticket после handshake, и стек обрабатывает его при чтении — захват
раньше завершения обмена вернёт «безбилетную» сессию. `SSL_SESSION`
иммутабельна и refcounted — шаринг между соединениями с разными контекстами
и из разных потоков безопасен. Если сервер сессию не принял (истекла,
рестарт), OpenSSL штатно откатывается на полный handshake. Факт resumption
проверяется через `SSL_session_reused`; клиент выводит счётчик
`TLS sessions resumed: N/M`.

## Тестирование

Тестового фреймворка нет: каждый тест — программа с `main()`, где функция
`check()` считает ошибки, а ненулевой код выхода означает провал. Запуск —
через CTest (`ctest --test-dir build --output-on-failure`), имена тестов:
`packet_tests`, `client_tests`, `operation_deadline_tests`,
`client_integration_tests`, `log_payload_tests`, `tls_end_to_end_tests`
(таймаут 30 с задан для сетевых тестов и `operation_deadline_tests`).

- `tests/test_packet.cpp` — CRC32 (контрольные векторы), сериализация
  (golden-bytes формат), десериализация, граничные случаи, случайные
  round-trip. Покрывает `src/protocol.cpp` — именно его гоняет MSan.
- `tests/test_client.cpp` — юнит-тесты `BasicClient` на `FakeConnection`
  (без сети): порядок запрос/ответ, ошибки транспорта, повреждённые
  ответы, повторный вызов, неверный echo с корректным CRC, abort,
  единственное уведомление, размеры 0/65535, режим длительности, окно
  pipelining и гистограммы.
- `tests/test_operation_deadline.cpp` — юнит-тест `OperationDeadline`
  (без сети, только таймеры): поколенческая защита — отмена таймера
  повышает поколение, и готовый callback старого таймера не отменяет
  следующую операцию.
- `tests/test_client_integration.cpp` — `BasicClient` против реального
  TCP-echo на loopback, включая фрагментированные ответы (по байту).
- `tests/test_log_payload.cpp` — экранирование полезной нагрузки.
- `tests/test_tls_end_to_end.cpp` — сквозной TLS-тест: реальный `TlsServer`
  и `TlsClient` на loopback с самоподписанным сертификатом, сгенерированным
  в памяти через OpenSSL (файлы не нужны). Порт 0 = эфемерный. Проверяются
  доверие/неизвестный CA/срок/имя сертификата, таймауты зависших узлов,
  ограничения сессий и payload, drain и многопоточные граничные пакеты,
  session resumption (второе соединение с захваченной сессией обязано
  пройти сокращённый handshake, `SSL_session_reused`).

Покрытие кода (gcov, нужны GCC/Clang):

```bash
./scripts/coverage.sh   # отчёт в build/coverage/coverage-report/
```

## Санитайзеры

ASan и TSan — отдельные сборки Clang, никогда не включаются вместе.
После `ctest` обязателен прогон обоих бинарников:

```bash
cmake -S . -B build/asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address
cmake --build build/asan --parallel 2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ctest --test-dir build/asan --output-on-failure
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 python3 scripts/sanitizer_smoke.py build/asan
```

(TSan аналогично с `-fsanitize=thread`,
`TSAN_OPTIONS=halt_on_error=1:exitcode=66`.)

MSan применяется только к коду пакетов (`src/protocol.cpp` +
`tests/test_packet.cpp`) через `scripts/msan_packet_test.sh` — нужен
инструментированный libc++ (CI собирает LLVM 18.1.8, кеширует и вызывает
скрипт с префиксом). Сервер и клиент под MSan не проверяются: для
достоверности пришлось бы инструментировать Boost, OpenSSL и spdlog.

## Фаззинг

Парсер пакетов фаззится libFuzzer'ом (тот же контур, что у MSan —
`src/protocol.cpp`, цель `fuzz/fuzz_packet.cpp`). Вход трактуется как сырой
кадр (заголовок 14 байт + нагрузка); цель проверяет, что принятый пакет
сериализуется обратно байт в байт, а `packet_error_name`/`calculate_crc32`
не падают на любых данных. Сборка Clang с `-fsanitize=fuzzer,address`,
сидовый корпус генерируется скриптом в `build/fuzz/corpus`:

```bash
bash scripts/fuzz_packet.sh 60   # аргумент — лимит секунд (по умолчанию 60)
```

Найденные падения сохраняются как `build/fuzz/crash-*`; воспроизведение:
`build/fuzz/fuzz_packet <crash-файл>`.

## CI/CD и релизы

- `ci.yml` срабатывает на push и PR в `master` и вручную: матрица
  GCC/Clang Debug с флагами `-Wall -Wextra -Wpedantic -Werror`, задача Windows/MSVC с vcpkg, задачи
  санитайзеров (address, thread), MSan-задача, fuzz-задача (libFuzzer по
  парсеру пакетов, 60 с; краши публикуются артефактом), задача покрытия
  (публикует `coverage.md` в summary), задача clang-format (проверка стиля
  по `.clang-format`, clang-format-18), проверка `py_compile` для
  `scripts/*.py` и `bash -n` для `scripts/*.sh`.
- `release.yml` срабатывает на тег `v*` (и вручную): задача `create-release`
  создаёт релиз один раз (до параллельных сборок, иначе задачи конкурентно
  вызвали бы `gh release create`), затем Release-сборка и тесты на Linux
  и Windows, упаковка `tls-echo-server-<tag>-linux-x86_64.tar.gz` и
  `tls-echo-server-<tag>-windows-x86_64.zip` + SHA-256, публикация в GitHub
  Releases через `gh`. Windows-задача использует статический triplet
  `x64-windows-static` + `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`
  (статический CRT /MT — обязателен для этого triplet, иначе LNK2038):
  exe самодостаточны, без DLL зависимостей (в отличие от динамического
  `x64-windows` в Debug-задаче ci.yml). Задача
  `create-release` также проверяет, что тег совпадает с `project(VERSION)`
  в `CMakeLists.txt` и `version-string` в `vcpkg.json` — при рассинхроне
  релиз падает до сборок. Новый релиз — через `scripts/bump-version.sh
  X.Y.Z` (бамп версии в обоих файлах + коммит + аннотированный тег),
  затем `git push origin master --follow-tags` (тег уезжает вместе с веткой).

## Соглашения по стилю

- Стандарт — C++17; CI собирает с `-Wall -Wextra -Wpedantic -Werror`,
  предупреждения недопустимы.
- Стиль кода формализован в `.clang-format` (база Google: 4 пробела,
  100 колонок, `case` с отступом, `#include` не сортируются) и проверяется
  задачей clang-format в CI (clang-format-18). Перед коммитом прогоняйте
  `clang-format -i` по изменённым файлам.
- Комментарии в коде — на русском; сообщения в `std::cout`/`std::cerr`
  и строки журналов (logger->info/warn/...) — на английском: журналы
  парсятся инструментами и читаются в mix-окружениях. Справка `--help`
  и описания опций CLI — на английском (исторический стиль файла).
  docstring'и Python-скриптов и интерфейсные комментарии — на английском
  (сохраняйте язык изменяемого файла).
- Асинхронные операции завершаются цепочками колбэков; общее состояние
  защищается strand'ами (`control_strand_`, strand клиента и каждой серверной сессии), а не мьютексами.
- Буферы для асинхронных операций держатся в `std::shared_ptr`, захваченном
  колбэком, — lifetime буфера привязан к операции.
- Все значения на проводе — в сетевом порядке байт; размер заголовка
  зафиксирован `static_assert`.
- Аргументы командной строки через `boost::program_options`, обязательные
  параметры (`--cert`, `--key`, `--host`) помечаются `required()`;
  ошибки парсиния выводятся в `stderr` с кодом выхода 1.
- Тесты пишутся по существующему шаблону: анонимный namespace, `check()`,
  подсчёт `failures`, `return 1` при провалах. Новым тестам, использующим
  сеть, задавайте эфемерный порт (0) и осмысленный таймаут. Для исходящих
  соединений используйте `127.0.0.1` / `address_v4::loopback()`. Адрес
  `endpoint(tcp::v4(), port)` означает wildcard `0.0.0.0` для bind;
  Winsock не допускает такой адрес назначения в connect.

## Соображения безопасности

- Приватные ключи и сертификаты не коммитятся: `.gitignore` исключает
  `*.key`, `*.pem`, `*.rsa` (кроме `*.pub`) и `*.log`. Локальные
  сертификаты создавайте через `scripts/generate-certs.sh`.
- Журнал уровня `debug` содержит данные пакетов (экранированные, но всё же)
  — не включайте его в проде с чувствительными данными.
- Клиент по умолчанию проверяет цепочку доверия и имя сервера. Самоподписанный
  сертификат передавайте через `--cert`. `--insecure` в C++ и Python-клиентах
  предназначен только для явной локальной проверки. Smoke-тест использует `--cert`.
- Сервер проверяет `len` по `--max-payload` до выделения буфера; предел протокола
  остаётся 65535 байт. Активные сессии ограничены `--max-connections`, включая
  handshake; зависшие операции закрываются по таймауту.
- Windows: не добавляйте `<arpa/inet.h>`; используйте `wire.h`. CMake явно
  задаёт MSVC `/utf-8 /EHsc`, поскольку CI может переопределить стандартные
  `CMAKE_CXX_FLAGS`. Не отключайте обработку исключений и не подавляйте C4530.
  В vcpkg явно указывайте `boost-asio`: остальные компоненты Boost не заменяют
  этот пакет. CMake-пресеты требуют ≥ 3.20, обычная сборка ≥ 3.16.
