  📊 Текущее состояние (что есть):

  ✅ Криптография (30% готовности)
  - X25519 key generation
  - ECDH key exchange
  - AES-GCM шифрование
  - Базовые тесты

  ❌ Отсутствует всё остальное

  ---
  🎯 Что нужно для децентрализованного мессенджера:

  1. Транспортный слой (P2P сеть)

  Текущее состояние: Только заглушка scripts/start_daemon.sh с несуществующим p2pd

  Необходимо:
  # Опции реализации:

  # A) libp2p (рекомендуется для Web3)
  pip install py-libp2p
  # + DHT для peer discovery
  # + mDNS для локальной сети
  # + Relay servers для NAT traversal

  # B) Простой TCP/UDP + hole punching
  # asyncio + socket programming
  # + STUN/TURN серверы для NAT

  # C) Гибридный подход
  # WebRTC для браузеров
  # + Native sockets для desktop/mobile

  Файлы для создания:
  - network/transport.py — абстракция транспорта
  - network/libp2p_client.py — libp2p обертка
  - network/peer_manager.py — управление подключениями
  - network/nat_traversal.py — пробивание NAT

  ---
  2. Протокол обмена сообщениями

  Текущее состояние: Пустой messages/protocol.py

  Необходимо:
  // messages/proto/message.proto
  syntax = "proto3";

  message Envelope {
    uint32 version = 1;           // Версия протокола
    string message_id = 2;        // UUID сообщения
    string sender_id = 3;         // Публичный ключ отправителя
    string recipient_id = 4;      // Публичный ключ получателя
    int64 timestamp = 5;          // Unix timestamp
    bytes encrypted_payload = 6;  // Зашифрованные данные
    bytes signature = 7;          // Ed25519 подпись
  }

  message Payload {
    MessageType type = 1;
    oneof content {
      TextMessage text = 2;
      FileMessage file = 3;
      SystemMessage system = 4;
    }
  }

  enum MessageType {
    TEXT = 0;
    FILE = 1;
    TYPING = 2;
    READ_RECEIPT = 3;
    CONTACT_REQUEST = 4;
  }

  Файлы для создания:
  - messages/proto/ — Protobuf определения
  - messages/envelope.py — обертка сообщений
  - messages/serialization.py — сериализация/десериализация
  - messages/validation.py — валидация структуры

  Зависимости:
  pip install protobuf grpcio-tools
  python -m grpc_tools.protoc -I. --python_out=. messages/proto/*.proto

  ---
  3. Расширенная криптография

  Текущее состояние: Только X25519 + AES-GCM

  Необходимо добавить:

  # crypto/signatures.py
  from cryptography.hazmat.primitives.asymmetric import ed25519

  class MessageSigner:
      """Ed25519 подписи для non-repudiation"""
      def sign(self, message: bytes, private_key) -> bytes
      def verify(self, message: bytes, signature: bytes, public_key) -> bool

  # crypto/identity.py
  class Identity:
      """Пара ключей: X25519 (шифрование) + Ed25519 (подписи)"""
      x25519_keypair: X25519KeyPair
      ed25519_keypair: Ed25519KeyPair
      fingerprint: str  # SHA-256 хэш публичных ключей

  # crypto/double_ratchet.py (опционально, для Forward Secrecy)
  class DoubleRatchet:
      """Signal Protocol Double Ratchet Algorithm"""
      # Обеспечивает:
      # - Forward secrecy (компрометация текущего ключа не раскрывает прошлые сообщения)
      # - Break-in recovery (восстановление безопасности после компрометации)

  Зависимости:
  # Для Signal Protocol (если нужен Double Ratchet)
  pip install pyaxolotl-curve25519

  ---
  4. Хранилище данных

  Текущее состояние: Только файлы PEM ключей

  Необходимо:

  # storage/database.py
  import sqlite3  # или PostgreSQL для production

  class MessageStore:
      """Хранилище сообщений"""
      def save_message(msg: Message) -> None
      def get_conversation(peer_id: str) -> List[Message]
      def mark_as_read(message_id: str) -> None
      def search_messages(query: str) -> List[Message]

  # storage/keystore.py
  from cryptography.fernet import Fernet

  class SecureKeyStore:
      """Зашифрованное хранилище ключей"""
      def __init__(self, master_password: str):
          self.key = self._derive_key(master_password)

      def save_identity(identity: Identity) -> None
      def load_identity() -> Identity
      # Хранит ключи в формате:
      # encrypted_data = Fernet(key).encrypt(private_key_pem)

  # storage/contacts.py
  class ContactManager:
      """База контактов"""
      def add_contact(name: str, public_key: str, fingerprint: str)
      def verify_fingerprint(peer_id: str, fingerprint: str) -> bool
      def get_contact_list() -> List[Contact]

  SQL Schema:
  CREATE TABLE messages (
      id TEXT PRIMARY KEY,
      peer_id TEXT NOT NULL,
      sender_is_me BOOLEAN,
      content TEXT,  -- расшифрованный текст
      timestamp INTEGER,
      status TEXT,   -- 'sent', 'delivered', 'read'
      FOREIGN KEY (peer_id) REFERENCES contacts(id)
  );

  CREATE TABLE contacts (
      id TEXT PRIMARY KEY,  -- публичный ключ
      name TEXT,
      fingerprint TEXT,
      verified BOOLEAN DEFAULT 0,
      last_seen INTEGER
  );

  Зависимости:
  pip install sqlalchemy  # ORM (опционально)

  ---
  5. Обнаружение пиров (Peer Discovery)

  Необходимо:

  # network/discovery.py

  class PeerDiscovery:
      """Методы обнаружения пиров"""

      # 1. DHT (Distributed Hash Table)
      async def announce_presence(self, peer_id: str) -> None:
          """Публикует свой ID в Kademlia DHT"""

      async def find_peer(self, peer_id: str) -> List[NetworkAddress]:
          """Ищет пира по ID в DHT"""

      # 2. Bootstrap nodes
      BOOTSTRAP_NODES = [
          "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
          # ... другие узлы
      ]

      # 3. mDNS для локальной сети
      async def discover_local_peers(self) -> List[Peer]:
          """Находит пиры в LAN через multicast"""

  # network/rendezvous.py
  class RendezvousServer:
      """Точка встречи для пиров за NAT"""
      # Relay сервер для hole punching
      async def coordinate_connection(peer_a: str, peer_b: str)

  Зависимости:
  pip install aiodns  # для mDNS

  ---
  6. Синхронизация и доставка

  # sync/message_queue.py
  class MessageQueue:
      """Очередь неотправленных сообщений"""
      pending: List[Message]
      retry_policy: RetryPolicy

      async def send_with_retry(self, msg: Message) -> bool
      async def handle_offline_peer(self, peer_id: str)

  # sync/receipt_tracker.py
  class ReceiptTracker:
      """Отслеживание статусов доставки"""
      def track_message(msg_id: str)
      def on_delivery_confirmed(msg_id: str)
      def on_read_receipt(msg_id: str)

  ---
  7. Пользовательский интерфейс

  Опции:

  A) CLI (текущий подход)
  pip install click prompt-toolkit rich
  # rich — для красивого форматирования
  # prompt-toolkit — для интерактивного ввода

  B) TUI (Terminal UI)
  pip install textual  # современный TUI фреймворк

  Пример структуры:
  # ui/tui_app.py
  from textual.app import App
  from textual.widgets import Header, Footer, ListView, Input

  class MessengerTUI(App):
      """Textual-based интерфейс"""
      def compose(self):
          yield Header()
          yield ContactList()
          yield ChatWindow()
          yield MessageInput()
          yield Footer()

  C) Desktop GUI
  pip install PyQt6  # или
  pip install tkinter  # встроен в Python

  D) Web UI
  pip install fastapi uvicorn websockets
  # REST API + WebSocket для real-time
  # Frontend: React/Vue.js

  ---
  8. Управление сессиями

  # session/connection_manager.py
  class ConnectionManager:
      """Управление активными соединениями"""
      active_peers: Dict[str, PeerConnection]

      async def connect_to_peer(peer_id: str) -> PeerConnection
      async def disconnect(peer_id: str)
      async def broadcast_presence()  # "я онлайн"

  # session/state_machine.py
  class PeerState(Enum):
      OFFLINE = 0
      CONNECTING = 1
      ONLINE = 2
      AWAY = 3

  class SessionManager:
      """Управление статусами"""
      def set_status(status: PeerState)
      def handle_reconnection()

  ---
  9. Дополнительные компоненты

  # utils/logging_config.py
  import logging
  # Структурированное логирование
  # для отладки P2P взаимодействий

  # utils/config.py
  import yaml
  class Config:
      """Загрузка из config.yaml"""
      bootstrap_nodes: List[str]
      listen_port: int
      database_path: str
      log_level: str

  # security/rate_limiter.py
  class RateLimiter:
      """Защита от спама"""
      def check_rate(peer_id: str, action: str) -> bool

  # security/blocklist.py
  class BlocklistManager:
      """Блокировка нежелательных пиров"""
      def block_peer(peer_id: str, reason: str)
      def is_blocked(peer_id: str) -> bool

  ---
  📦 Полный список зависимостей

  Создайте requirements.txt:

  # Криптография
  cryptography>=42.0.0

  # P2P networking
  py-libp2p>=0.2.0
  aiodns>=3.1.0

  # Протоколы
  protobuf>=4.25.0
  grpcio-tools>=1.60.0

  # Хранилище
  sqlalchemy>=2.0.0

  # UI (выберите один вариант)
  # Опция A: CLI
  click>=8.1.0
  prompt-toolkit>=3.0.0
  rich>=13.7.0

  # Опция B: TUI
  textual>=0.47.0

  # Опция C: Web
  # fastapi>=0.109.0
  # uvicorn>=0.27.0
  # websockets>=12.0

  # Утилиты
  pyyaml>=6.0.0
  python-dotenv>=1.0.0

  ---
  🗂️ Целевая структура проекта

  dmess-cli-master/
  ├── cli.py                          # Точка входа CLI
  ├── requirements.txt                # Зависимости
  ├── config.yaml                     # Конфигурация
  ├── .env                            # Секреты (игнорировать в git)
  │
  ├── crypto/                         # ✅ Криптография
  │   ├── keys.py                     # Генерация и хранение ключей
  │   ├── e2e.py                      # E2E шифрование (текущая логика)
  │   ├── signatures.py               # 🆕 Ed25519 подписи
  │   ├── identity.py                 # 🆕 Управление идентичностью
  │   └── double_ratchet.py           # 🆕 Forward secrecy (опционально)
  │
  ├── messages/                       # ✅ Протокол сообщений
  │   ├── protocol.py                 # Базовые определения
  │   ├── proto/                      # 🆕 Protobuf схемы
  │   │   ├── message.proto
  │   │   └── *_pb2.py               # Сгенерированные файлы
  │   ├── envelope.py                 # 🆕 Обертки сообщений
  │   ├── serialization.py            # 🆕 Сериализация
  │   └── validation.py               # 🆕 Валидация
  │
  ├── network/                        # 🆕 Сетевой слой
  │   ├── transport.py                # Абстракция транспорта
  │   ├── libp2p_client.py            # libp2p интеграция
  │   ├── peer_manager.py             # Управление пирами
  │   ├── discovery.py                # Peer discovery (DHT, mDNS)
  │   ├── rendezvous.py               # Relay сервер
  │   └── nat_traversal.py            # STUN/TURN
  │
  ├── storage/                        # 🆕 Хранилище
  │   ├── database.py                 # SQLite/PostgreSQL
  │   ├── keystore.py                 # Зашифрованное хранилище ключей
  │   ├── contacts.py                 # Управление контактами
  │   └── migrations/                 # SQL миграции
  │
  ├── sync/                           # 🆕 Синхронизация
  │   ├── message_queue.py            # Очередь отправки
  │   ├── receipt_tracker.py          # Статусы доставки
  │   └── conflict_resolver.py        # Разрешение конфликтов
  │
  ├── session/                        # 🆕 Управление сессиями
  │   ├── connection_manager.py       # Активные соединения
  │   └── state_machine.py            # Статусы пиров
  │
  ├── ui/                             # 🆕 Пользовательский интерфейс
  │   ├── cli_app.py                  # Click-based CLI
  │   ├── tui_app.py                  # Textual TUI (опционально)
  │   └── api/                        # REST API (опционально)
  │       ├── routes.py
  │       └── websocket_handler.py
  │
  ├── security/                       # 🆕 Безопасность
  │   ├── rate_limiter.py             # Защита от спама
  │   └── blocklist.py                # Блокировка пиров
  │
  ├── utils/                          # 🆕 Утилиты
  │   ├── logging_config.py           # Настройка логов
  │   ├── config.py                   # Загрузка конфигурации
  │   └── exceptions.py               # Кастомные исключения
  │
  ├── daemon/                         # Переименовать daemon.py/ → daemon/
  │   ├── __init__.py
  │   ├── client.py                   # Клиент демона
  │   └── server.py                   # 🆕 Серверная часть
  │
  ├── scripts/
  │   ├── start_daemon.sh             # ✅ Скрипт запуска
  │   ├── generate_proto.sh           # 🆕 Компиляция Protobuf
  │   └── setup_bootstrap.sh          # 🆕 Настройка bootstrap узлов
  │
  └── tests/
      ├── test_crypto.py              # Расширенные тесты крипто
      ├── test_protocol.py            # 🆕 Тесты протокола
      ├── test_network.py             # 🆕 Тесты P2P
      ├── test_storage.py             # 🆕 Тесты БД
      └── integration/                # 🆕 Интеграционные тесты
          └── test_e2e_messaging.py

  ---
  🚀 Roadmap реализации

  Этап 1: Фундамент (1-2 недели)

  1. ✅ Рефакторинг существующего кода
    - Вынести функции из cli.py в модули
    - Исправить баги (опечатки, структура каталогов)
  2. Расширенная криптография
    - crypto/signatures.py — Ed25519 подписи
    - crypto/identity.py — управление парой ключей
  3. Хранилище
    - storage/keystore.py — защищенное хранение ключей
    - storage/database.py — SQLite для сообщений
    - storage/contacts.py — управление контактами

  Этап 2: Протокол (1 неделя)

  1. Определить Protobuf схемы (messages/proto/)
  2. Реализовать сериализацию/десериализацию
  3. Валидация и версионирование сообщений

  Этап 3: P2P сеть (2-3 недели)

  1. Интеграция libp2p
    - Базовые подключения peer-to-peer
    - DHT для обнаружения пиров
  2. NAT traversal (STUN/TURN)
  3. Relay сервер для офлайн доставки

  Этап 4: Логика мессенджера (2 недели)

  1. Отправка/получение сообщений
  2. Очередь и retry логика
  3. Статусы доставки (delivered/read)
  4. Управление контактами

  Этап 5: UI (1-2 недели)

  1. TUI интерфейс (Textual)
  2. Список контактов
  3. Окно чата
  4. Уведомления

  Этап 6: Production-готовность (2 недели)

  1. Обработка ошибок
  2. Логирование
  3. Конфигурация
  4. Полное покрытие тестами
  5. Документация

  ---
  💡 Альтернативные подходы

  Если хотите ускорить разработку:

  1. Использовать существующие фреймворки:
  - https://matrix.org/ — открытый протокол для федеративных мессенджеров
  pip install matrix-nio  # Python SDK
  - https://xmpp.org/ — проверенный временем протокол
  pip install slixmpp

  2. Гибридная архитектура:
  - Оставить вашу криптографию (X25519 + AES-GCM)
  - Использовать готовый транспорт (Matrix/XMPP)
  - Получить федерацию "бесплатно"

  3. Прогрессивное развертывание:
  - MVP: CLI + локальная сеть (mDNS) + SQLite
  - v1.0: + libp2p + DHT + TUI
  - v2.0: + Double Ratchet + Web UI + Mobile clients

  ---
  📚 Рекомендуемые ресурсы

  Документация:

  - https://docs.libp2p.io/concepts/
  - https://signal.org/docs/
  - https://protobuf.dev/programming-guides/proto3/

  Референсные проекты:

  - https://briarproject.org/ — decentralized messenger (Java)
  - https://jami.net/ — P2P messenger (C++)
  - https://getsession.org/ — fork Signal (onion routing)

  Книги:

  - "Designing Data-Intensive Applications" — Martin Kleppmann
  - "Bulletproof SSL and TLS" — Ivan Ristić

  ---