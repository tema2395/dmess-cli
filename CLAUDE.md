# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Обзор проекта

`dmess-cli` — прототип CLI-приложения для end-to-end шифрования сообщений на Python. Реализует полный криптографический цикл: генерация ключей X25519, ECDH-обмен, деривация общего секрета через HKDF и симметричное шифрование AES-GCM.

**Требования**: Python 3.10+
**Единственная зависимость**: `cryptography` (библиотека PyCA)
**Общий объем кода**: ~192 строки Python (включая тесты)
**Статус**: Рабочий прототип без production-готовых компонентов

### Криптографический стек

| Компонент | Алгоритм | Параметры |
|-----------|----------|-----------|
| Асимметричное шифрование | X25519 (Curve25519) | ECDH key exchange |
| Деривация ключа | HKDF | SHA-256, info=`b'dmess-cli-ecdh'`, no salt |
| Симметричное шифрование | AES-GCM | 256-bit key, 12-byte nonce, no AAD |
| Формат ключей | PEM | PKCS#8 (private), SubjectPublicKeyInfo (public) |

## Команды разработки

### Первоначальная настройка
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install cryptography
```

### Основные команды CLI
```bash
# Генерация пары ключей
python cli.py gen_keys
# → Создает keys/private_key.pem и keys/public_key.pem

# Шифрование сообщения
python cli.py encrypt --peer-key keys/public_key.pem --message "Текст сообщения"
# → Создает encrypted_message.bin (nonce + ciphertext)

# Расшифровка
python cli.py decrypt --peer-key keys/public_key.pem --file encrypted_message.bin
# → Выводит: "Decrypted message: Текст сообщения"
```

### Тестирование
```bash
# Все тесты
python -m unittest tests/test.py

# Конкретный тест
python -m unittest tests.test.TestCliApp.test_encrypt_decrypt

# Verbose mode
python -m unittest tests/test.py -v
```

## Архитектура проекта

### Структура файлов
```
dmess-cli-master/
├── cli.py                      # Монолитный модуль: вся логика (117 LOC)
├── tests/test.py               # Модульные тесты (75 LOC)
├── crypto/                     # Заглушки для будущей модуляризации
│   ├── keys.py                 # (пустой) - управление ключами
│   └── e2e.py                  # (пустой) - E2E логика
├── messages/
│   └── protocol.py             # (пустой) - версионирование протокола
├── daemon.py/
│   └── client.py               # (3 LOC) - импорты asyncio/multiformats
├── scripts/
│   └── start_daemon.sh         # Скрипт запуска p2pd (бинарник отсутствует)
└── keys/                       # Создается автоматически при gen_keys
    ├── private_key.pem         # X25519 приватный ключ
    └── public_key.pem          # X25519 публичный ключ
```

### Детальный анализ cli.py

#### Граф зависимостей функций
```
main (args parser)
    ├── generate_keys()
    │   ├── x25519.X25519PrivateKey.generate()
    │   ├── private_key.public_key()
    │   └── writes to keys/
    │
    ├── encrypt_message(peer_key_file, message)
    │   ├── generate_shared_key(peer_key_file)
    │   │   ├── load_pem_private_key()
    │   │   ├── load_pem_public_key()
    │   │   ├── private_key.exchange(peer_public_key)
    │   │   └── HKDF.derive(shared_key)
    │   ├── AESGCM(derived_key)
    │   ├── os.urandom(12)  # nonce generation
    │   └── writes nonce + ciphertext to encrypted_message.bin
    │
    └── decrypt_message(peer_key_file, encrypted_file)
        ├── generate_shared_key(peer_key_file)
        ├── reads encrypted_message.bin
        ├── splits nonce ([:12]) and ciphertext ([12:])
        └── AESGCM.decrypt(nonce, ciphertext)
```

#### Криптографический поток (подробно)

**1. Генерация ключей (cli.py:30-42)**
```python
private_key = x25519.X25519PrivateKey.generate()  # 32 байта случайных данных
public_key = private_key.public_key()              # Умножение на базовую точку кривой
```
- **Формат хранения**: PEM-encoded (Base64 + headers)
- **Приватный ключ**: PKCS#8 без шифрования (`NoEncryption()`)
- **Публичный ключ**: SubjectPublicKeyInfo (стандарт X.509)

**2. ECDH обмен и деривация ключа (cli.py:46-63)**
```python
shared_key = private_key.exchange(peer_public_key)  # 32-байтовый общий секрет
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,              # Длина AES-256 ключа
    salt=None,              # ⚠️ Без соли (снижает энтропию при слабом shared_key)
    info=b'dmess-cli-ecdh'  # Domain separation string
).derive(shared_key)
```
- **Математика ECDH**: `shared_secret = private_A × public_B = private_B × public_A`
- **HKDF**: Расширяет 32-байтовый shared secret до криптографически стойкого ключа
- **Info string**: Предотвращает повторное использование ключей в разных контекстах

**3. Шифрование (cli.py:67-74)**
```python
nonce = os.urandom(12)                          # 96-битный случайный nonce
ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # AAD = None
output = nonce + ciphertext                     # Простая конкатенация
```
- **AES-GCM**: Authenticated Encryption with Associated Data (AEAD)
- **Тег аутентификации**: 16 байт, добавляется автоматически к ciphertext
- **Размер выходного файла**: `12 (nonce) + len(plaintext) + 16 (tag)` байт

**4. Расшифровка (cli.py:77-84)**
```python
nonce, encrypted = data[:12], data[12:]
plaintext = aesgcm.decrypt(nonce, encrypted, None)
```
- **Верификация тега**: Происходит автоматически в `decrypt()`
- **Исключение при ошибке**: `cryptography.exceptions.InvalidTag`

### Формат зашифрованного файла

```
encrypted_message.bin:
┌──────────────┬───────────────────────────┬──────────────┐
│  Nonce       │  Ciphertext               │  Auth Tag    │
│  12 bytes    │  len(plaintext) bytes     │  16 bytes    │
└──────────────┴───────────────────────────┴──────────────┘
```

**Нет**:
- Версионирования формата
- Магических байтов (magic number)
- Метаданных (timestamp, sender ID)
- Сжатия

### Тестовая инфраструктура

**tests/test.py** (75 строк):
- **Изоляция**: Каждый тест работает в `tempfile.mkdtemp()`
- **Запуск CLI**: Через `subprocess.run(['python', cli_path, ...])`
- **3 тестовых сценария**:
  1. `test_gen_keys`: Проверка создания файлов ключей
  2. `test_encrypt_decrypt`: E2E тест с сообщением на кириллице
  3. `test_encrypt_missing_message_argument`: Валидация argparse

**Особенности**:
- Тесты используют "self-encryption" (peer-key = собственный public key)
- Это математически корректно для X25519, но не отражает реальный обмен ключами
- Нет тестов на:
  - Невалидные ключи
  - Поврежденный ciphertext
  - Неправильный nonce
  - Межплатформенную совместимость (Windows/Linux)

## Анализ безопасности

### ⚠️ Критические проблемы

1. **Незащищенное хранение ключей** (cli.py:36)
   ```python
   NoEncryption()  # Приватный ключ в plain text
   ```
   - **Риск**: Кража ключа из файловой системы
   - **Решение**: Шифрование через passphrase (используя `BestAvailableEncryption(password)`)

2. **Отсутствие обработки ошибок**
   - Нет try-except блоков
   - При отсутствии файлов → некрасивый traceback
   - При InvalidTag → exception без контекста

3. **Нет проверки целостности ключей**
   - Приватный/публичный ключи могут быть несогласованы
   - Нет валидации формата PEM перед загрузкой

4. **Жестко заданные пути**
   - `keys/`, `encrypted_message.bin` — хардкод
   - Невозможно указать альтернативные директории

### ✅ Криптографически корректные решения

1. **X25519 + HKDF**: Стандартная связка для key exchange
2. **AES-GCM**: Современный AEAD-алгоритм (рекомендован NIST)
3. **12-байтовый nonce**: Оптимальный размер для GCM
4. **Случайная генерация nonce**: `os.urandom()` — CSPRNG

### ⚡ Потенциальные векторы атак

1. **Подмена ключей** (Man-in-the-Middle)
   - Нет механизма верификации peer-key (fingerprints, certificates)
   - Атакующий может подставить свой публичный ключ

2. **Replay attack**
   - Отсутствует счетчик сообщений (sequence number)
   - Зашифрованное сообщение можно переслать повторно

3. **Directory traversal**
   - `--peer-key ../../../etc/passwd` — нет валидации путей
   - Возможна попытка чтения чувствительных файлов

4. **Nonce reuse** (теоретически)
   - При `os.urandom()` вероятность коллизии `1 / 2^96` (пренебрежимо мала)
   - Но при использовании слабого PRNG (в будущих модификациях) — критично

## Известные баги

1. **Опечатка в выводе** (cli.py:74)
   ```python
   print("Message ecnrypted ...")  # "encrypted" написано как "ecnrypted"
   ```

2. **Опечатка в help** (cli.py:96)
   ```python
   '--message', help="Mesage to encrypt"  # "Message" написано как "Mesage"
   ```

3. **Некорректная структура каталогов**
   - `daemon.py/client.py` — каталог назван как Python-модуль
   - Должно быть `daemon/client.py` или `daemon.py` как файл

## Отсутствующие компоненты

### Нет в проекте:
- ❌ `requirements.txt` / `pyproject.toml`
- ❌ Версионирование (git tags, CHANGELOG)
- ❌ CI/CD (GitHub Actions, pre-commit hooks)
- ❌ Логирование (только print-ы)
- ❌ Конфигурационные файлы
- ❌ Документация API (docstrings есть только в тестах)

### Заглушки (stub files):
- `crypto/keys.py` (0 байт)
- `crypto/e2e.py` (0 байт)
- `messages/protocol.py` (0 байт)
- `daemon.py/client.py` (3 строки импортов)

## План будущего развития (из README.md)

### Краткосрочные улучшения (Python):
1. Добавить `requirements.txt` с pinned версиями
2. Модуляризация: вынести функции из `cli.py` в `crypto/`
3. Обработка ошибок: try-except блоки + custom exceptions
4. Логирование через `logging` вместо `print`
5. Конфигурация: `config.yaml` для путей и параметров
6. Расширенные тесты: negative cases, mock filesystem

### Долгосрочная трансформация (Rust):
- Переписать на Rust 2021+ с `tokio` (async runtime)
- Web3 интеграция: `ethers-rs` для работы с Ethereum
- Транспортный слой: `rust-libp2p` для p2p коммуникации
- Подписи сообщений: Ed25519 для non-repudiation
- Хранилище: `sled` или `redb` для encrypted key storage
- Протокол: Protobuf/Cap'n Proto для версионируемого формата сообщений

### Архитектурные изменения:
```
Текущее состояние:          Целевая архитектура:
cli.py (монолит)     →      crypto/ (keys, e2e, signatures)
                            messages/ (protocol v1, v2, ...)
                            daemon/ (libp2p transport)
                            storage/ (encrypted key vault)
                            web3/ (ethers integration)
                            cli/ (clap-based interface)
```

## Рекомендации по работе с кодом

### При добавлении новых функций:
1. **Читайте существующий cli.py перед изменениями** — вся логика там
2. **Сохраняйте обратную совместимость** — формат `encrypted_message.bin` не должен меняться без версионирования
3. **Тестируйте с русским текстом** — проект изначально работает с UTF-8 кириллицей
4. **Не забывайте про `os.makedirs(KEYS_DIR, exist_ok=True)`** — директория keys должна создаваться автоматически

### При рефакторинге:
1. **Начните с crypto/keys.py** — вынесите функции управления ключами
2. **Используйте crypto/e2e.py для ECDH+HKDF** — отделите обмен ключами от шифрования
3. **messages/protocol.py** — добавьте версионирование формата (magic bytes + version field)
4. **Создайте requirements.txt** — закрепите `cryptography==<version>`

### При тестировании:
- Запускайте тесты в чистой временной директории
- Проверяйте работу с non-ASCII символами
- Тестируйте некорректные входные данные (corrupted keys, tampered ciphertext)
