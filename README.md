# 🌴 tropico

**LLM Honeypot**

**Paramiko-based custom SSH server running inside Docker, simulating a real login shell environment in LLM mode or real mode.**

---

## 🚀 Features:

- Python SSH server using **Paramiko**.
- **LLM-Backed Fake Terminal Mode (Default Mode):**
  - Commands are passed to an OpenAI-compatible LLM API (e.g., GPT models).
  - **Per-session memory:** Commands and their outputs are remembered during each SSH session (e.g., `mkdir` persists across `ls` commands).
  - **Realistic prompt and environment.**
- **Real Bash login shell mode:**
  - Loads `.bashrc`, `.bash_profile`, environment variables, aliases, virtualenv, etc.
- SSH server listens on **port 22 inside Docker**, mapped to **port 2222 on host**.
- Default user credentials:
  - **Username:** `admin`
  - **Password:** `password`

---

## 🔑 Environment Variables

Create a `.env` file in the project root:

```
# OpenAI API key for LLM Mode
OPENAI_API_KEY=sk-your-api-key

# Select model (e.g., gpt-3.5-turbo, gpt-4-turbo, etc.)
OPENAI_MODEL=gpt-3.5-turbo

# Default user & host info (affects prompt)
DEFAULT_USER=admin
DEFAULT_HOSTNAME=virtual-machine
USER_PASSWORD=password
```

---

## 🐳 Usage:

### 1. **Build and run Docker Compose image and service:**

```bash
docker compose up --build -d
```

Or use the included `run.sh` script.

---

### 2. **SSH into the server:**

```bash
ssh admin@127.0.0.1 -p 2222
```
(Default password: `password`)

---

### 3. **Shut down the server:**

```bash
docker compose down
```

Or use the included `stop.sh` script.


## 🌐 HTTPS Fake Server (LLM-powered)

In addition to the SSH honeypot, this project includes a **fake HTTPS server powered by an LLM model**, designed to behave like a valid HTTPS server when accessed via browsers or curl clients.

---

### 🚀 Features:

- **Valid HTTPS server behavior:**
  - Uses a TLS certificate (self-signed by default) to perform proper TLS handshake.
  - Listens on **port 443**.
  - Responds with correct HTTP/1.1 headers.

- **Dynamic LLM-based HTML content:**
  - Each HTTP request triggers an OpenAI-compatible LLM to generate realistic HTML content.
  - Simulates a real website serving valid HTML pages.

- **Compatible with browsers and curl:**
  - Appears like a real HTTPS server when accessed.
  - No visible signs of being simulated.

---

### 🔑 Environment Variables:

The HTTPS server uses the same `.env` configuration as the SSH service:

```
OPENAI_API_KEY=sk-your-api-key
OPENAI_MODEL=gpt-3.5-turbo
```

---

### 🐳 Usage:

**Start both SSH and HTTPS services together:**

```bash
docker compose up --build -d
```

---

### 🌐 Access:

Visit:

```
https://localhost
```

Or:

```bash
curl -k https://localhost
```

---

### 🛠 Certificates:

- By default, the HTTPS server uses a **self-signed TLS certificate** (`cert.pem` & `key.pem`).
- You can replace these files with your own certificates (e.g., using [mkcert](https://github.com/FiloSottile/mkcert)) to avoid browser trust warnings.