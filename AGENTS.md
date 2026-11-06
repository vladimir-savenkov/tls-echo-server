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
- OpenSSL (TLS 1.2)
- spdlog (асинхронное журналирование: файл + цветной stdout)
- Python 3 (вспомогательные клиенты и проверки CI)
- Зависимости: системные пакеты Ubuntu (`libboost-all-dev`, `libssl-dev`,
  `libspdlog-dev`) либо vcpkg по манифесту `vcpkg.json`

## Сетевая архитектура и протокол

- Бинарный протокол: заголовок `PacketHeader` (ровно 10 байт,
  `#pragma pack(push, 1)`, проверяется `static_assert`) — `uint32 id`,
  `uint16 len`, `uint32 crc`, затем полезная нагрузка `len` байт.
- Все поля заголовка передаются в сетевом порядке байт (переносимые функции `wire::to_network16/32` и `wire::from_network16/32`
  из `include/wire.h`; POSIX-заголовки не нужны).
- CRC32 (полином zlib `0xEDB88320`) считается по полезной нагрузке;
  максимальный размер пакета — 65535 байт (`uint16_t`).
- Сервер: `TlsServer` — один `io_context` на пуле потоков, акцептор и
  реестр сессий живут на `control_strand_`; у каждой сессии собственный
  strand для сокета и таймера, lifetime держится через `shared_from_this`. Корректное завершение по SIGINT/SIGTERM:
  акцептор закрывается, активным сессиям даётся 5 секунд (настраивается),
  затем их сокеты закрываются; цикл обрабатывает отменённые операции до выхода.
  Не заменяйте это на `io_context_.stop()`: он оставляет обработчики в очереди.
- Клиент: `TlsClient` (resolve → connect → handshake) + `TlsConnection`
  (низкоуровневые async_write/read через strand) + `BasicClient<Connection>`
  — шаблонный класс логики запрос/ответ, параметризованный «соединением»
  с интерфейсом `async_write / async_read_exactly / close / abort`. Это позволяет
  тестировать логику на поддельных соединениях без сети.
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
  `stats()` читает атомарные счётчики; согласованный итог получают после join.
- `ClientRunOptions`: размер бинарных данных и длительность на соединение
  после handshake; в режиме длительности текущий запрос завершается до shutdown.
  `LatencyStats` — ограниченная гистограмма (512 интервалов, 8 на удвоение),
  p50/p95/p99 являются верхними границами с погрешностью до 9.1% от 1 мкс.
  Задержка DNS+TCP+TLS измеряется отдельно от запроса.
- Журналирование: логгеры spdlog передаются как `std::shared_ptr` и
  внедряются в классы; на уровне `debug` логируются состояния всех
  асинхронных операций и данные пакетов (непечатные байты экранируются
  функцией `escape_log_payload` из `include/log_payload.h`).

## Структура каталогов

- `include/` — заголовки: `protocol.h` (формат пакета, `Packet`,
  `calculate_crc32`), `server.h` (`TlsServer` + вложенный `Session`),
  `client.h` (`TlsConnection`, `TlsClient`), `basic_client.h`
  (`BasicClient<Connection>`, `ClientError`, `ClientRunOptions`),
  `log_payload.h`, `wire.h`, `operation_deadline.h`, `latency_stats.h`.
- `src/` — `main.cpp` (точка входа сервера), `server.cpp`, `main_client.cpp`
  (точка входа клиента), `client.cpp`, `protocol.cpp`.
- `tests/` — пять самодостаточных тестов (без фреймворка, см. ниже).
- `scripts/` — `generate-certs.sh` (самоподписанный сертификат),
  `sanitizer_smoke.py` (прогон сервера и клиента под санитайзерами),
  `msan_packet_test.sh`, `coverage.sh`, `multi_client_test.py`,
  `interactive_client.py`.
- `CMakeLists.txt` — единственный файл сборки: статическая библиотека
  `protocol`, исполняемые файлы `server` и `client`, пять тестов.
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
`--log-file` (по умолчанию `server.log`), `--log-level`. У клиента `--host`
обязателен. Проверка TLS включена по умолчанию: `--cert` задаёт доверенный CA,
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
несовместим с явным `--packets`). Клиент выводит throughput, MiB/с полезных
данных и квантили задержек. Полный список — через `--help`.

## Тестирование

Тестового фреймворка нет: каждый тест — программа с `main()`, где функция
`check()` считает ошибки, а ненулевой код выхода означает провал. Запуск —
через CTest (`ctest --test-dir build --output-on-failure`), имена тестов:
`packet_tests`, `client_tests`, `client_integration_tests`,
`log_payload_tests`, `tls_end_to_end_tests` (сетевые тесты имеют таймаут 30 с).

- `tests/test_packet.cpp` — CRC32 (контрольные векторы), сериализация
  (golden-bytes формат), десериализация, граничные случаи, случайные
  round-trip. Покрывает `src/protocol.cpp` — именно его гоняет MSan.
- `tests/test_client.cpp` — юнит-тесты `BasicClient` на `FakeConnection`
  (без сети): порядок запрос/ответ, ошибки транспорта, повреждённые
  ответы, повторный вызов, неверный echo с корректным CRC, abort,
  единственное уведомление, размеры 0/65535, режим длительности и гистограммы.
- `tests/test_client_integration.cpp` — `BasicClient` против реального
  TCP-echo на loopback, включая фрагментированные ответы (по байту).
- `tests/test_log_payload.cpp` — экранирование полезной нагрузки.
- `tests/test_tls_end_to_end.cpp` — сквозной TLS-тест: реальный `TlsServer`
  и `TlsClient` на loopback с самоподписанным сертификатом, сгенерированным
  в памяти через OpenSSL (файлы не нужны). Порт 0 = эфемерный. Проверяются
  доверие/неизвестный CA/срок/имя сертификата, таймауты зависших узлов,
  ограничения сессий и payload, drain и многопоточные граничные пакеты.

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

## CI/CD и релизы

- `ci.yml` срабатывает на push и PR в `master` и вручную: матрица
  GCC/Clang Debug с флагами `-Wall -Wextra -Wpedantic -Werror`, задача Windows/MSVC с vcpkg, задачи
  санитайзеров (address, thread), MSan-задача, задача покрытия
  (публикует `coverage.md` в summary), проверка `py_compile` для
  `scripts/*.py` и `bash -n` для `scripts/*.sh`.
- `release.yml` срабатывает на тег `v*` (и вручную): Release-сборка,
  тесты, упаковка `tls-echo-server-<tag>-linux-x86_64.tar.gz` + SHA-256,
  публикация в GitHub Releases через `gh`. Новый релиз — аннотированный
  тег: `git tag -a v1.0.1 -m "..." && git push origin v1.0.1`.

## Соглашения по стилю

- Стандарт — C++17; CI собирает с `-Wall -Wextra -Wpedantic -Werror`,
  предупреждения недопустимы.
- Комментарии и пользовательские сообщения — на русском; docstring'и
  Python-скриптов и интерфейсные комментарии — на английском (сохраняйте
  язык изменяемого файла).
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
  сеть, задавайте эфемерный порт (0) и осмысленный таймаут.

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
