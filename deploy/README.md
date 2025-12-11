# Deployment guide (server 206.81.17.31)

Вариант без домена: будет доступно по `http://206.81.17.31:8000/`. Для красивого HTTPS добавьте домен и прокси (см. ниже).

## 1) Подготовка (один раз)
```bash
sudo useradd -m -s /bin/bash dmess || true
sudo apt-get update && sudo apt-get install -y python3 python3-venv git nginx

sudo mkdir -p /opt/dmess
sudo chown dmess:dmess /opt/dmess
sudo -u dmess git clone https://github.com/tema2395/dmess-cli.git /opt/dmess
cd /opt/dmess
sudo -u dmess python3 -m venv .venv
sudo -u dmess /opt/dmess/.venv/bin/pip install -r requirements.txt
```

## 2) Systemd юниты
Отредактируйте пути/имя узла при необходимости (файлы уже в `deploy/`):
```bash
sudo cp /opt/dmess/deploy/relay.service /etc/systemd/system/
sudo cp /opt/dmess/deploy/api.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable relay.service api.service
sudo systemctl start relay.service api.service
sudo systemctl status relay.service api.service
```

По умолчанию:
- Relay слушает `0.0.0.0:7001`
- API/Web UI слушает `0.0.0.0:8000`, имя узла `ServerNode`, ключи в `/opt/dmess/keys-server`
- Relay host захардкожен на `206.81.17.31` (замените при переносе)

## 3) Firewall
Открыть порты 7001 (relay) и 8000 (UI) или проксируем 8000 через nginx:
```bash
sudo ufw allow 7001/tcp
sudo ufw allow 8000/tcp
# или только 80/443 если будете проксировать
```

## 4) Nginx (опционально, HTTPS)
Шаблон `deploy/nginx.conf.sample`:
```bash
sudo cp /opt/dmess/deploy/nginx.conf.sample /etc/nginx/sites-available/dmess
sudo ln -s /etc/nginx/sites-available/dmess /etc/nginx/sites-enabled/dmess
sudo nginx -t && sudo systemctl reload nginx
```
Обновите `server_name` и при наличии домена прогоните certbot:
```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d chat.example.com
```

## 5) Обновление
```bash
cd /opt/dmess
sudo -u dmess git pull
sudo -u dmess /opt/dmess/.venv/bin/pip install -r requirements.txt
sudo systemctl restart relay.service api.service
```

## 6) Подключение клиента
- Ссылку для браузера: `http://206.81.17.31:8000/` (или ваш домен/https).
- CLI/другой узел: `python ui/cli_chat.py --name Friend --keys-dir keys-friend --relay-host 206.81.17.31 --relay-port 7001`

## 7) Замены по вкусу
- Поменяйте имя узла: в `/opt/dmess/deploy/api.service` аргумент `--name`.
- Ключи сервера хранятся в `/opt/dmess/keys-server`; при первом запуске сгенерируются.
- Если n8n уже слушает 443/5678 — конфликтов нет, порты 7001/8000 свободны.
