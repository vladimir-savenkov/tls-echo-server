# TLS Echo Server

Асинхронные TLS echo-сервер и клиент на C++17 с бинарным протоколом и CRC32.

## Особенности

- **Протокол:** заголовок с ID, длиной и CRC32, затем данные пакета.
- **Соединения:** TLS через OpenSSL, асинхронный ввод-вывод через Boost.Asio.
- **Нагрузка:** один процесс клиента создаёт несколько TLS-соединений и обрабатывает
  их в общем пуле потоков.
- **Журнал:** spdlog; на уровне `debug` видны состояния асинхронных операций,
  номера пакетов и их данные.
- **Завершение:** сервер обрабатывает SIGINT и SIGTERM, давая сеансам время закончить.

## Технологии

- C++17
- Boost.Asio, Boost.Program_options
- OpenSSL
- spdlog
- CMake

## Сборка и тесты

На Ubuntu установите зависимости:

```bash
sudo apt-get update
sudo apt-get install build-essential clang cmake ninja-build openssl python3 \
  libboost-all-dev libssl-dev libspdlog-dev
```

Из корня проекта:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

Исполняемые файлы: `build/server` и `build/client`. Для оптимизированной сборки
используйте отдельный каталог:

```bash
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --parallel 2
```

## CI/CD

GitHub Actions запускает CI при push в `master`, для pull request в `master` и
вручную через `workflow_dispatch`. CI собирает Debug-версию с GCC и Clang и
запускает C++ тесты. Отдельные сборки с AddressSanitizer (ASan) и
ThreadSanitizer (TSan) также запускают тесты, затем поднимают TLS-сервер,
передают 100 пакетов через 20 соединений клиента и проверяют завершение сервера
по SIGTERM. ASan проверяет ошибки памяти и утечки при выходе процесса;
TSan проверяет гонки данных. Эти проверки выполняются в разных процессах и
сборках: ASan и TSan не включаются одновременно.

Отдельная задача MemorySanitizer (MSan) проверяет чтение неинициализированных
данных в коде пакетов и CRC32, запуская `tests/test_packet.cpp`. Для неё CI
собирает инструментированную libc++ из исходников LLVM 18.1.8 и кеширует
результат. Системная библиотека C++ без инструментирования даёт ложные
сообщения MSan. Сервер и клиент в MSan-задачу не входят: для достоверной
проверки их пришлось бы также собрать с MSan все сторонние библиотеки,
включая Boost, OpenSSL и spdlog. ASan и TSan продолжают проверять оба бинарника.

Локально можно повторить проверки (нужны Clang и OpenSSL CLI):

```bash
cmake -S . -B build/asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address
cmake --build build/asan --parallel 2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ctest --test-dir build/asan --output-on-failure
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 python3 scripts/sanitizer_smoke.py build/asan

cmake -S . -B build/tsan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ \
  '-DCMAKE_CXX_FLAGS=-fsanitize=thread -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=thread
cmake --build build/tsan --parallel 2
TSAN_OPTIONS=halt_on_error=1:exitcode=66 ctest --test-dir build/tsan --output-on-failure
TSAN_OPTIONS=halt_on_error=1:exitcode=66 python3 scripts/sanitizer_smoke.py build/tsan
```

Для локального запуска MSan после сборки инструментированной libc++ используйте
`bash scripts/msan_packet_test.sh /путь/к/msan-libcxx`. Команды сборки libc++
приведены в задаче `memory-sanitizer` файла `.github/workflows/ci.yml`.

Тег вида `v1.0.0` запускает Release workflow: он собирает и тестирует проект,
затем публикует Linux-архив и контрольную сумму SHA-256 в GitHub Releases.

Чтобы создать новый релиз, создайте аннотированный тег и отправьте его в GitHub:

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

После отправки тега GitHub Actions запустит Release workflow и опубликует
архив в разделе GitHub Releases. Номер версии в имени тега следует менять для
каждого следующего релиза, например `v1.0.1` или `v1.1.0`.

## Как запустить

1. Соберите проект по инструкции выше и сгенерируйте самоподписанный сертификат:

   ```bash
   bash scripts/generate-certs.sh
   ```

2. Запустите сервер:

   ```bash
   ./build/server --cert server.crt --key server.key
   ```

Сервер по умолчанию слушает порт `8443` и использует 4 рабочих потока. Для
вывода всех аргументов и значений по умолчанию запустите `./build/server --help`.

Для остановки нажмите `Ctrl+C` (SIGINT) или отправьте SIGTERM. Сервер прекращает
принимать новые соединения и ждёт завершения активных сеансов до 5 секунд. Если
сеансы не закончились за это время, сервер останавливает цикл обработки событий
и выходит. При обычном закрытии соединения выполняется TLS shutdown.

## Нагрузочная проверка C++ клиентом

```bash
./build/client --host localhost --port 8443 --clients 100 --threads 4 --packets 20
```

`--clients` задаёт число одновременных TLS-соединений (по умолчанию 1),
`--packets` — число запросов на каждом соединении (по умолчанию 5), а
`--threads` — число потоков общего цикла обработки событий (по умолчанию 1).
Порт по умолчанию — `8443`; `--host` обязателен. Все аргументы показаны в
`./build/client --help`.
После завершения клиент выводит число успешных соединений и ответов; при
ошибках возвращает ненулевой код выхода. Для подробного журнала добавьте
`--log-level debug`.

## Журналирование

По умолчанию сервер пишет в `server.log`, клиент — в `client.log`; уровень
журнала — `info`. Пути и уровень можно задать через `--log-file` и
`--log-level`. Например, в разных терминалах:

```bash
./build/server --cert server.crt --key server.key \
  --log-level debug --log-file server-debug.log
./build/client --host localhost --clients 2 --packets 3 \
  --log-level debug --log-file client-debug.log
```

На уровне `debug` записываются запуск и результат асинхронных операций,
состояния клиента, порядковый номер и данные каждого отправленного и полученного
пакета. Непечатные байты данных экранируются. Учитывайте, что журнал на этом
уровне содержит содержимое пакетов.

## Python-утилиты

Параллельная проверка нескольких TLS-соединений:

```bash
python3 scripts/multi_client_test.py --host localhost --port 8443 \
  --clients 10 --messages 5 --insecure
```

Интерактивный клиент:

```bash
python3 scripts/interactive_client.py --host localhost --port 8443 --insecure
```

`--insecure` предназначен только для локальной проверки. Для проверки
сертификата передайте CA или самоподписанный сертификат сервера:

```bash
python3 scripts/interactive_client.py --ca-cert path/to/server.crt
```
