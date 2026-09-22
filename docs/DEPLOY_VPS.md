# Deployment to Timeweb Cloud (Ubuntu 24.04)

Target: a public `https://<domain>` URL with the jury endpoint at `POST /process`.

## 1. DNS

Create an `A` record for the selected domain or subdomain pointing to the VPS public IPv4 address.

Example:

```text
Type: A
Name: alfa
Value: <VPS_PUBLIC_IP>
TTL: 300
```

Wait until `nslookup <domain>` returns the VPS IP. Do not start Caddy before DNS points to this server.

## 2. Connect to the server

From Windows PowerShell:

```powershell
ssh root@<VPS_PUBLIC_IP>
```

## 3. Install Git and Docker

Run on the VPS as `root`:

```bash
apt-get update
apt-get install -y ca-certificates curl git openssl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker compose version
```

## 4. Give the VPS read-only access to the private repository

Generate a dedicated deploy key on the VPS:

```bash
ssh-keygen -t ed25519 -C "alfa-vibe-vps" -f /root/.ssh/id_ed25519 -N ""
cat /root/.ssh/id_ed25519.pub
```

Copy only the printed public key. In GitHub open:

`sofiaaslanian/alfa-vibe → Settings → Deploy keys → Add deploy key`

Name: `alfa-vibe-vps`. Leave **Allow write access** disabled.

Then on the VPS:

```bash
ssh-keyscan github.com >> /root/.ssh/known_hosts
chmod 600 /root/.ssh/known_hosts
git clone git@github.com:sofiaaslanian/alfa-vibe.git /opt/alfa-vibe
cd /opt/alfa-vibe
```

## 5. Configure secrets

```bash
cd /opt/alfa-vibe
cp .env.example .env
nano .env
```

Replace at least:

- `DOMAIN` with the real domain, without `https://`;
- `ACME_EMAIL` with a team email;
- `ALFAGEN_API_KEY` with the real key, or leave the placeholder for a no-LLM demo;
- `STATE_HMAC_KEY` and `STATE_ENC_KEY` with separate outputs of `openssl rand -hex 32`;
- `PROXY_API_KEYS` with an output of `openssl rand -hex 24`.

Never commit `.env` or paste its values into chats/screenshots.

## 6. Open only required ports

In the Timeweb firewall/security-group UI allow inbound TCP:

- `22` — SSH, preferably only from the team's IP;
- `80` — HTTP and certificate issuance;
- `443` — HTTPS.

Do not open `6379` or `8080`.

## 7. Start the service

```bash
cd /opt/alfa-vibe
docker compose config
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 proxy
docker compose logs --tail=100 caddy
```

Caddy obtains and renews HTTPS certificates automatically after DNS resolves to the server and ports 80/443 are reachable.

## 8. Verify the public contract

```bash
curl -fsS https://<domain>/ready
curl -fsS https://<domain>/health

curl -fsS -X POST https://<domain>/process \
  -H "Content-Type: application/json" \
  -d '{"payload":"Клиент ivanov@mail.ru","payload_id":"deploy-check-1"}'
```

Take the masked `result` from the last response and send it again with the same `payload_id`. The response must restore the original string.

The URL for the organizers is:

```text
https://<domain>
```

Their endpoint will be:

```text
POST https://<domain>/process
```

## 9. Update from GitHub

After changes are merged into `main`:

```bash
cd /opt/alfa-vibe
git pull --ff-only origin main
docker compose up -d --build
docker compose ps
```

## 10. Rollback

Before every deployment note the current commit:

```bash
cd /opt/alfa-vibe
git rev-parse HEAD
```

To roll back, checkout a previously verified commit and rebuild. Do not delete the Redis volume during the hackathon because it contains live mask/demask state.
