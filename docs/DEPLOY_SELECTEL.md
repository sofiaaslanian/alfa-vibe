# Deployment to Selectel

Goal: publish the UI at `https://<domain>/` and the jury contract at
`POST https://<domain>/process`.

This guide is for a Selectel cloud server with a public IPv4 address.

## 1. Collect the server values

In the Selectel control panel:

1. Open **Products → Cloud Servers → the server → Ports** and copy the public IP.
2. Open the server's **Console** tab and note the Linux login.
3. Confirm the operating system and available RAM on the server page.

Do not send the server password, private SSH key, AlfaGen key or `.env` contents
to chats.

## 2. Point the domain to the VPS

Create an `A` record for the selected domain or subdomain:

```text
Type: A
Name: alfa
Value: <SELECTEL_PUBLIC_IPV4>
TTL: 300
```

If DNS is hosted by Selectel, use **Products → DNS Hosting → Domain zones**.
If DNS is hosted elsewhere, create the record at that DNS provider.

Verify from the local computer:

```powershell
nslookup <domain>
```

The returned IPv4 address must match the Selectel public IP.

## 3. Configure the Selectel security group

Allow inbound TCP traffic:

- `22` — SSH, preferably only from the team's current IP;
- `80` — HTTP redirect and certificate issuance;
- `443` — HTTPS.

Do not open `6379` or `8080`. Redis and FastAPI are reachable only inside
the Docker network.

## 4. Connect from Windows

```powershell
ssh <login>@<SELECTEL_PUBLIC_IPV4>
```

Use the login displayed in the Selectel **Console** tab. Do not assume it is
always `root`.

## 5. Install Docker if it is not already installed

First check:

```bash
docker --version
docker compose version
```

If either command is missing, install Docker from its official Ubuntu
repository:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker compose version
```

## 6. Give the VPS read-only access to the private repository

Generate a dedicated key on the VPS:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
ssh-keygen -t ed25519 -C "alfa-vibe-selectel" -f ~/.ssh/alfa_vibe_deploy -N ""
cat ~/.ssh/alfa_vibe_deploy.pub
```

Copy only the printed public key. The repository owner then opens:

`sofiaaslanian/alfa-vibe → Settings → Deploy keys → Add deploy key`

Use the name `alfa-vibe-selectel` and leave **Allow write access** disabled.

Configure Git to use this key:

```bash
ssh-keyscan github.com >> ~/.ssh/known_hosts
chmod 600 ~/.ssh/known_hosts

cat >> ~/.ssh/config <<EOF
Host github-alfa-vibe
  HostName github.com
  User git
  IdentityFile ~/.ssh/alfa_vibe_deploy
  IdentitiesOnly yes
EOF
chmod 600 ~/.ssh/config
```

Clone the deployment branch:

```bash
sudo mkdir -p /opt/alfa-vibe
sudo chown "$USER":"$USER" /opt/alfa-vibe
git clone --branch main git@github-alfa-vibe:sofiaaslanian/alfa-vibe.git /opt/alfa-vibe
cd /opt/alfa-vibe
```

## 7. Create the server-only environment file

```bash
cd /opt/alfa-vibe
cp .env.example .env
nano .env
```

Replace:

- `DOMAIN` — the real domain without `https://`;
- `ACME_EMAIL` — team email;
- `STATE_HMAC_KEY` — first output of `openssl rand -hex 32`;
- `STATE_ENC_KEY` — second, different output;
- `PROXY_API_KEYS` — output of `openssl rand -hex 24`;
- `ALFAGEN_API_KEY` — real key only when testing the LLM proxy.

Keep `NER_ENABLED=0` for the public load-test image. The slim Docker image does
not install torch/RuBERT. The official `/process` path uses rules and does not
require AlfaGen.

Never commit `.env`.

## 8. Start the stack

```bash
cd /opt/alfa-vibe
sudo docker compose config
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail=100 proxy
sudo docker compose logs --tail=100 caddy
```

Caddy will request an HTTPS certificate after DNS resolves to the VPS and ports
80/443 are reachable.

## 9. Verify the public URL

```bash
curl -fsS https://<domain>/ready
curl -fsS https://<domain>/health

curl -fsS -X POST https://<domain>/process \
  -H "Content-Type: application/json" \
  -d '{"payload":"Клиент ivanov@mail.ru","payload_id":"selectel-check-1"}'
```

Send the returned masked result again with the same `payload_id`. The second
response must restore the original string.

The submission URL is:

```text
https://<domain>
```

The AlfaSonar endpoint is:

```text
POST https://<domain>/process
```

## 10. Load gate before submission

Run from a different machine, not from inside the VPS:

```bash
python scripts/load_smoke.py --url https://<domain> --n 2000 --concurrency 100 --mode create
python scripts/load_smoke.py --url https://<domain> --profile 100k --mode create --n 20 --concurrency 4
```

Record the server resources, commit SHA, p50/p95/p99, RPS and error rate.

## 11. Update from main

After each stable commit is merged into `main`:

```bash
cd /opt/alfa-vibe
git pull --ff-only origin main
sudo docker compose up -d --build
sudo docker compose ps
```

Do not remove the Redis volume during an active test: it contains mask/demask
state.
