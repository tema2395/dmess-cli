# dMess Web Frontend

Директория `frontend/` содержит только фронтенд (HTML/JS/CSS). Все API/WS предоставляет бэкенд в `ui/api_server.py`.

Основные эндпоинты:
- `GET /` — отдает `frontend/index.html`.
- `GET /api/self` — данные о текущем пире: `peer_id`, `mode`, `sig_key` (Ed25519 pubkey).
- `GET /api/peers` — список пиров (id, name, sig_key).
- `POST /api/send` — отправка сообщения, тело: `{"peer": "...", "text": "..."}`.
- `WS /ws` — входящие события (`welcome` с сигнатурой и `msg`).

Транспорт шифрует и подписывает сообщения на бэкенде; фронтенд показывает fingerprint и обрезку Ed25519 для сверки. Шьете UI, не трогая серверную логику.***/ End Patch​
