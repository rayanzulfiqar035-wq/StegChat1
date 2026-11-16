# Secure E2EE Messenger

A client-server web messaging app for an information-security course project featuring end-to-end encryption and steganography.

## Run the App

### 1. Prerequisites & Virtual Environment
Ensure Python 3.10+ is installed. Create and activate a virtual environment, then install dependencies:
```bash
python -m venv venv
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. TLS Certificates (mkcert)
The application runs strictly over HTTPS. Install [mkcert](https://github.com/FiloSottile/mkcert) and generate locally trusted certificates:
```bash
# 1. Install mkcert local CA (run once)
mkcert -install

# 2. Generate certificates in certs/
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1 ::1
```

### 3. Environment Configuration
Copy `.env.example` to `.env` and configure a strong `SECRET_KEY`:
```bash
cp .env.example .env
```
Generate a random secret key and set it in `.env`:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Start the Server
Run the Flask server:
```bash
python app.py
```

Open your browser and navigate to:
```
https://localhost:5000
```
