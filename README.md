# 🌴 tropico

**LLM Honeypot**

**Paramiko-based custom SSH server running inside Docker, simulating a real login shell environment with user profiles, correct prompt behavior, and environment variables.**

---

## 🚀 Features:

- Python SSH server using **Paramiko**.
- **Real Bash login shell behavior:**
  - Loads `.bashrc`, `.bash_profile`, environment variables, aliases, virtualenv, etc.
- SSH server listens on **port 22 inside Docker**, mapped to **port 2222 on host**.
- Fixed container name: **`tropico-poc-container`** for predictable usage.
- Default user credentials:
  - **Username:** `admin`
  - **Password:** `password`

---

## 🔑 Environment Variables

- Create a `.env` file in the project root:
```
OPENAI_API_KEY=sk-your-api-key
```
- You can switch to `gpt-4-turbo` or other supported models (default is gpt-3.5-turbo).
```
OPENAI_MODEL=gpt-3.5-turbo
```
- Define the default user, hostname and login password:
```
DEFAULT_USER=admin
DEFAULT_HOSTNAME=virtual-machine
USER_PASSWORD=password
```
## 🐳 Usage:

### 1. **Build and run Docker Compose image and service:**

```bash
docker compose up --build -d
```

or the included `run.sh` script.

### 2. **Build and run Docker Compose image and service:**

```bash
docker compose down
```
or the included `stop.sh` script.



