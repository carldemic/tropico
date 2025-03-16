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
- User credentials:
  - **Username:** `admin`
  - **Password:** `9999`

---

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



