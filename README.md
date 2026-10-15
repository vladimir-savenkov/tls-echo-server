# TLS Echo Server

Асинхронный TLS-сервер на C++17 с бинарным протоколом, CRC32 и пулами объектов.
Проект демонстрирует понимание сетевого программирования, криптографии, управления памятью и безопасности.

## Особенности

- **Протокол:** Бинарный формат пакета (Header: ID, Len, CRC + Payload).
- **Безопасность:** TLS 1.2/1.3 (OpenSSL), проверка целостности данных (CRC32).
- **Производительность:** Асинхронность (Boost.Asio), пул объектов (Object Pool), асинхронный логгер (spdlog).
- **Память:** Строгое соблюдение RAII, отсутствие утечек, выравнивание структур.
- **Тестируемость:** Архитектура готова для внедрения моков (Dependency Injection).

## Технологии

- C++17
- Boost.Asio + Boost.Beast
- OpenSSL
- spdlog
- CMake

## CI/CD

GitHub Actions собирает проект с GCC и Clang и запускает все тесты при каждом
push в `master` и для pull request. Тег вида `v1.0.0` запускает Release workflow,
который повторно собирает и тестирует проект, затем публикует Linux-архив и его
SHA-256 checksum в GitHub Releases.

Чтобы создать новый релиз, создайте аннотированный тег и отправьте его в GitHub:

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

После отправки тега GitHub Actions запустит Release workflow и опубликует
архив в разделе GitHub Releases. Номер версии в имени тега следует менять для
каждого следующего релиза, например `v1.0.1` или `v1.1.0`.

## Как запустить

1. Сгенерируйте сертификаты:
   ```bash
   cd scripts
   chmod +x generate_certs.sh
   ./generate_certs.sh
   ```

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
