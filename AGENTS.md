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
- Все поля заголовка передаются в сетевом порядке байт (`htonl`/`htons`).
- CRC32 (полином zlib `0xEDB88320`) считается по полезной нагрузке;
  максимальный размер пакета — 65535 байт (`uint16_t`).
- Сервер: `TlsServer` — один `io_context` на пуле потоков, акцептор и
  счётчик сессий живут на `control_strand_`; каждая сессия держит себя
  через `shared_from_this`. Корректное завершение по SIGINT/SIGTERM:
  акцептор закрывается, активным сессиям даётся 5 секунд, затем
  `io_context_.stop()`.
- Клиент: `TlsClient` (resolve → connect → handshake) + `TlsConnection`
  (низкоуровневые async_write/read через strand) + `BasicClient<Connection>`
  — шаблонный класс логики запрос/ответ, параметризованный «соединением»
  с интерфейсом `async_write / async_read_exactly / close`. Это позволяет
  тестировать логику на поддельных соединениях без сети.
- ID пакетов клиента: `100 + номер_пакета`; клиент проверяет CRC и
  ожидаемый ID каждого ответа.
- Журналирование: логгеры spdlog передаются как `std::shared_ptr` и
  внедряются в классы; на уровне `debug` логируются состояния всех
  асинхронных операций и данные пакетов (непечатные байты экранируются
  функцией `escape_log_payload` из `include/log_payload.h`).

## Структура каталогов

- `include/` — заголовки: `protocol.h` (формат пакета, `Packet`,
  `calculate_crc32`), `server.h` (`TlsServer` + вложенный `Session`),
  `client.h` (`TlsConnection`, `TlsClient`), `basic_client.h`
  (`BasicClient<Connection>`, `ClientError`), `log_payload.h`.
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
./build/client --host localhost --port 8443 --clients 100 --threads 4 --packets 20
```

Важные опции сервера: `--port` (по умолчанию 8443), `--threads`,
`--log-file` (по умолчанию `server.log`), `--log-level`. У клиента `--host`
обязателен; без `--cert` проверка сертификата отключается (в журнале
предупреждение). Полный список — через `--help`.

## Тестирование

Тестового фреймворка нет: каждый тест — программа с `main()`, где макрос
`check()` считает ошибки, а ненулевой код выхода означает провал. Запуск —
через CTest (`ctest --test-dir build --output-on-failure`), имена тестов:
`packet_tests`, `client_tests`, `client_integration_tests`,
`log_payload_tests`, `tls_end_to_end_tests` (у последних двух таймаут 30 с).

- `tests/test_packet.cpp` — CRC32 (контрольные векторы), сериализация
  (golden-bytes формат), десериализация, граничные случаи, случайные
  round-trip. Покрывает `src/protocol.cpp` — именно его гоняет MSan.
- `tests/test_client.cpp` — юнит-тесты `BasicClient` на `FakeConnection`
  (без сети): порядок запрос/ответ, ошибки транспорта, повреждённые
  ответы, повторный вызов.
- `tests/test_client_integration.cpp` — `BasicClient` против реального
  TCP-echo на loopback, включая фрагментированные ответы (по байту).
- `tests/test_log_payload.cpp` — экранирование полезной нагрузки.
- `tests/test_tls_end_to_end.cpp` — сквозной TLS-тест: реальный `TlsServer`
  и `TlsClient` на loopback с самоподписанным сертификатом, сгенерированным
  в памяти через OpenSSL (файлы не нужны). Порт 0 = эфемерный.

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
  GCC/Clang Debug с флагами `-Wall -Wextra -Wpedantic -Werror`, задачи
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
  защищается strand'ами (`control_strand_`, strand клиента), а не мьютексами.
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
- Клиент без `--cert` отключает проверку TLS-сертификата — только для
  локальных самоподписанных сертификатов; `--insecure` в Python-скриптах
  предназначен только для локальной проверки.
- Сервер читает `len` из заголовка и резервирует буфер до 65535 байт на
  пакет — при изменениях протокола учитывайте это ограничение.
