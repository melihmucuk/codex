# ChatGPT Plus Entegrasyonu Rehberi

Bu döküman, Codex'in ChatGPT Plus entegrasyon mekanizmasını açıklar ve başka CLI'lara nasıl entegre edileceğini gösterir.

## Codex Nasıl Çalışıyor?

### 1. OAuth 2.0 Flow

```
┌──────────────┐
│   CLI Tool   │
└──────┬───────┘
       │
       ├─► 1. OAuth URL Oluştur
       │    • Endpoint: https://auth.openai.com/oauth/authorize
       │    • Client ID: app_EMoamEEZ73f0CkXaXp7hrann
       │    • PKCE: S256 code_challenge
       │    • Scopes: openid profile email offline_access
       │
       ├─► 2. Browser'da aç → Kullanıcı giriş yapar
       │
       ├─► 3. Authorization code al (callback: http://localhost:1455/auth/callback)
       │
       ├─► 4. Token Exchange
       │    POST https://auth.openai.com/oauth/token
       │    Body:
       │      - grant_type: authorization_code
       │      - code: <auth_code>
       │      - code_verifier: <pkce_verifier>
       │      - redirect_uri: http://localhost:1455/auth/callback
       │
       └─► 5. Token Set Döner:
            {
              "id_token": "eyJ...",       // JWT - Plan bilgisi burada!
              "access_token": "eyJ...",   // API istekleri için
              "refresh_token": "..."      // Token yenileme için
            }
```

### 2. Plan Bilgisi Extraction

JWT ID Token'ın payload'ında:

```json
{
  "email": "user@example.com",
  "https://api.openai.com/auth": {
    "chatgpt_plan_type": "plus",        // ← Plus aboneliği!
    "chatgpt_account_id": "org-xxxxx"
  },
  "exp": 1234567890,
  ...
}
```

**Kodda nasıl çıkarılır:**

```rust
// codex-rs/core/src/token_data.rs:90-115
pub fn parse_id_token(id_token: &str) -> Result<IdTokenInfo, IdTokenInfoError> {
    // JWT formatı: header.payload.signature
    let mut parts = id_token.split('.');
    let (_header_b64, payload_b64, _sig_b64) = ...;

    // Base64 decode
    let payload_bytes = base64::decode(payload_b64)?;
    let claims: IdClaims = serde_json::from_slice(&payload_bytes)?;

    // Plan tipini çıkar
    Ok(IdTokenInfo {
        email: claims.email,
        chatgpt_plan_type: claims.auth.chatgpt_plan_type,  // "plus"
        chatgpt_account_id: claims.auth.chatgpt_account_id,
        ...
    })
}
```

### 3. Token Storage

`~/.codex/auth.json`:

```json
{
  "tokens": {
    "id_token": "eyJhbGciOi...",
    "access_token": "eyJhbGci...",
    "refresh_token": "frt_xxxxx",
    "account_id": "org-xxxxx"
  },
  "last_refresh": "2025-12-20T10:30:00Z"
}
```

### 4. Auto-Refresh Mechanism

```rust
// codex-rs/core/src/auth.rs
// Token 8 günden eskiyse otomatik yenile
if needs_refresh {
    POST https://auth.openai.com/oauth/token
    Body:
      - grant_type: refresh_token
      - refresh_token: <refresh_token>
      - client_id: app_EMoamEEZ73f0CkXaXp7hrann

    // Yeni token set al ve kaydet
}
```

---

## Başka CLI'a Entegrasyon Yöntemleri

### Yöntem 1: Kendi OAuth Client ID'niz ile (Resmi Yol)

**Gereksinimler:**
- OpenAI'den OAuth client ID almak
- OAuth 2.0 + PKCE implementasyonu

**Avantajlar:**
✅ Tamamen bağımsız
✅ Kendi marka/uygulama adınız
✅ TOS uyumlu

**Dezavantajlar:**
❌ OpenAI approval gerekir
❌ Daha fazla development

**Örnek implementasyon (Python):**

```python
import secrets
import hashlib
import base64
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, parse_qs
import json

class ChatGPTAuth:
    def __init__(self, client_id):
        self.client_id = client_id
        self.issuer = "https://auth.openai.com"
        self.redirect_uri = "http://localhost:8080/callback"

    def generate_pkce(self):
        """PKCE code verifier ve challenge oluştur"""
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')

        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')

        return code_verifier, code_challenge

    def login(self):
        """OAuth flow başlat"""
        # 1. PKCE oluştur
        code_verifier, code_challenge = self.generate_pkce()

        # 2. Authorization URL
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = f"{self.issuer}/oauth/authorize?{urlencode(params)}"

        print(f"Tarayıcınızda açın: {auth_url}")

        # 3. Local server başlat ve authorization code bekle
        auth_code = self._start_callback_server()

        # 4. Token exchange
        token_response = requests.post(
            f"{self.issuer}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "code_verifier": code_verifier,
            }
        )

        tokens = token_response.json()

        # 5. Plan bilgisini çıkar
        plan_type = self._extract_plan_from_jwt(tokens['id_token'])

        # 6. Kaydet
        self._save_tokens(tokens, plan_type)

        return {
            "plan_type": plan_type,
            "email": self._extract_email_from_jwt(tokens['id_token']),
            "tokens": tokens
        }

    def _extract_plan_from_jwt(self, id_token):
        """JWT'den plan tipini çıkar"""
        parts = id_token.split('.')
        # Base64 padding ekle
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        auth_claims = payload.get('https://api.openai.com/auth', {})
        return auth_claims.get('chatgpt_plan_type', 'unknown')

    def _extract_email_from_jwt(self, id_token):
        """JWT'den email çıkar"""
        parts = id_token.split('.')
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get('email')

    def _save_tokens(self, tokens, plan_type):
        """Token'ları kaydet"""
        import os
        from pathlib import Path

        config_dir = Path.home() / ".your-cli"
        config_dir.mkdir(exist_ok=True)

        auth_file = config_dir / "auth.json"
        with open(auth_file, 'w') as f:
            json.dump({
                "tokens": tokens,
                "plan_type": plan_type,
                "last_updated": datetime.now().isoformat()
            }, f, indent=2)

    def _start_callback_server(self):
        """Callback için local server"""
        auth_code = None

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal auth_code
                if self.path.startswith('/callback'):
                    query = parse_qs(self.path.split('?')[1])
                    auth_code = query['code'][0]

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<h1>Success! You can close this window.</h1>')

        server = HTTPServer(('localhost', 8080), CallbackHandler)
        server.handle_request()  # Tek istek al ve kapat

        return auth_code

# Kullanım:
auth = ChatGPTAuth(client_id="your-client-id-from-openai")
result = auth.login()
print(f"Plan: {result['plan_type']}")  # "plus", "pro", "free", etc.
```

---

### Yöntem 2: Codex'in Token'larını Kullan (Hızlı Yol)

**Gereksinimler:**
- Kullanıcının Codex yüklü olması
- Kullanıcının `codex login` yapmış olması

**Avantajlar:**
✅ Çok hızlı implementasyon
✅ OAuth flow'a gerek yok
✅ Token refresh Codex tarafından yönetiliyor

**Dezavantajlar:**
❌ Codex'e dependency
❌ Kullanıcı her iki tool'u da kullanmalı

**Örnek implementasyon:**

```python
import json
from pathlib import Path
from datetime import datetime

class CodexTokenReader:
    """Codex'in auth.json dosyasından token oku"""

    def __init__(self):
        self.auth_file = Path.home() / ".codex" / "auth.json"

    def get_credentials(self):
        """ChatGPT credentials al"""
        if not self.auth_file.exists():
            raise FileNotFoundError(
                "Codex auth.json bulunamadı.\n"
                "Lütfen önce 'codex login' komutunu çalıştırın."
            )

        with open(self.auth_file) as f:
            auth_data = json.load(f)

        tokens = auth_data.get("tokens", {})

        if not tokens:
            raise ValueError("Codex auth.json'da token bulunamadı")

        # Plan tipini JWT'den çıkar
        id_token = tokens.get("id_token")
        plan_type = self._extract_plan_from_jwt(id_token)
        email = self._extract_email_from_jwt(id_token)

        return {
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token"),
            "account_id": tokens.get("account_id"),
            "id_token": id_token,
            "plan_type": plan_type,
            "email": email,
        }

    def _extract_plan_from_jwt(self, id_token):
        """JWT'den plan tipini çıkar"""
        import base64
        parts = id_token.split('.')
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        auth_claims = payload.get('https://api.openai.com/auth', {})
        return auth_claims.get('chatgpt_plan_type', 'free')

    def _extract_email_from_jwt(self, id_token):
        """JWT'den email çıkar"""
        import base64
        parts = id_token.split('.')
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get('email')

    def call_chatgpt_api(self, endpoint, method='GET', data=None):
        """ChatGPT backend API'ye istek at"""
        import requests

        creds = self.get_credentials()

        url = f"https://chatgpt.com/backend-api/{endpoint}"

        headers = {
            "Authorization": f"Bearer {creds['access_token']}",
            "Content-Type": "application/json",
        }

        if creds.get('account_id'):
            headers["chatgpt-account-id"] = creds['account_id']

        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)

        return response.json()

# Kullanım:
reader = CodexTokenReader()

try:
    creds = reader.get_credentials()
    print(f"Email: {creds['email']}")
    print(f"Plan: {creds['plan_type']}")  # "plus", "pro", "free"

    # ChatGPT API'ye istek at
    response = reader.call_chatgpt_api('conversations')
    print(f"Conversations: {response}")

except FileNotFoundError as e:
    print(f"Hata: {e}")
    print("Lütfen önce 'codex login' yapın.")
```

**CLI entegrasyonu:**

```bash
#!/bin/bash
# your-cli.sh

# Codex'in kurulu olup olmadığını kontrol et
if ! command -v codex &> /dev/null; then
    echo "Codex bulunamadı. Lütfen önce Codex'i yükleyin:"
    echo "  npm install -g @anthropic/codex"
    exit 1
fi

# Codex login durumunu kontrol et
if ! codex auth status &> /dev/null; then
    echo "Lütfen önce Codex ile giriş yapın:"
    echo "  codex login"
    exit 1
fi

# Python script'i çalıştır
python3 your_cli.py "$@"
```

---

### Yöntem 3: Hybrid Approach

En esnek çözüm:

```python
class ChatGPTAuthManager:
    """Hem kendi OAuth hem Codex token desteği"""

    def __init__(self, client_id=None):
        self.client_id = client_id
        self.codex_reader = CodexTokenReader()

    def login(self, method='auto'):
        """
        method:
          - 'auto': Önce Codex token dene, yoksa OAuth
          - 'codex': Sadece Codex token
          - 'oauth': Sadece kendi OAuth
        """
        if method == 'auto':
            try:
                return self.codex_reader.get_credentials()
            except FileNotFoundError:
                if not self.client_id:
                    raise ValueError(
                        "Codex token bulunamadı ve OAuth client ID verilmedi.\n"
                        "Lütfen 'codex login' yapın veya OAuth client ID sağlayın."
                    )
                return self._oauth_login()

        elif method == 'codex':
            return self.codex_reader.get_credentials()

        elif method == 'oauth':
            return self._oauth_login()

    def _oauth_login(self):
        """Kendi OAuth flow"""
        auth = ChatGPTAuth(self.client_id)
        return auth.login()

# Kullanım:
manager = ChatGPTAuthManager(client_id="your-id")  # Optional

# Otomatik: Codex varsa kullan, yoksa OAuth
creds = manager.login(method='auto')
print(f"Plan: {creds['plan_type']}")
```

---

## Karşılaştırma Tablosu

| Özellik | Kendi OAuth | Codex Token | Hybrid |
|---------|-------------|-------------|--------|
| Geliştirme süresi | Uzun | Çok kısa | Orta |
| Codex dependency | ❌ Yok | ✅ Gerekli | ⚠️ Opsiyonel |
| OpenAI approval | ✅ Gerekli | ❌ Gereksiz | ⚠️ Opsiyonel |
| Token refresh | ✅ Kendiniz yönetin | ✅ Codex yönetir | ✅ Her iki yol |
| Kullanıcı deneyimi | İyi | Harika (tek login) | En iyi |
| Maintenance | Orta | Düşük | Orta |

---

## Önerilen Strateji

### Kısa vadede (MVP):
1. **Yöntem 2** kullan (Codex token okuma)
2. Kullanıcılardan `codex login` yapmalarını iste
3. Hızlıca piyasaya çık

### Uzun vadede:
1. OpenAI'ye OAuth client ID başvurusu yap
2. **Yöntem 3** (Hybrid) implementasyonuna geç
3. Kullanıcılara seçenek sun:
   - Codex ile login (kolay)
   - Kendi CLI ile login (bağımsız)

---

## Örnek CLI Komutları

```bash
# Kullanıcı perspektifinden:

# Seçenek 1: Codex token kullan
$ codex login
$ your-cli run  # Otomatik Codex token'ı kullanır

# Seçenek 2: Kendi OAuth
$ your-cli login  # Kendi OAuth flow
$ your-cli run

# Seçenek 3: API key
$ export OPENAI_API_KEY=sk-...
$ your-cli run

# Plan kontrolü
$ your-cli status
✓ Logged in as: user@example.com
✓ Plan: ChatGPT Plus
✓ Access: Premium features enabled
```

---

## Güvenlik Notları

1. **Token Storage:**
   - Permissions: `chmod 600 ~/.your-cli/auth.json`
   - Encrypt at rest (opsiyonel)
   - Never commit to git

2. **Client ID:**
   - OpenAI'nin `app_EMoamEEZ73f0CkXaXp7hrann` client ID'sini KULLANMAYIN
   - TOS violation olabilir
   - Kendi client ID'nizi alın

3. **Token Refresh:**
   - Refresh token'ı güvenli sakla
   - Otomatik refresh implementasyonu gerekli
   - Hata durumunda re-login

4. **Rate Limiting:**
   - ChatGPT API rate limit'leri var
   - Plus kullanıcılar daha yüksek limit
   - Retry logic ekle

---

## Sonuç

**TL;DR:**
- ✅ Evet, entegre edilebilir
- 🚀 En hızlısı: Codex'in auth.json'ını oku
- 🎯 En iyisi: Kendi OAuth + Codex token hybrid
- ⚠️ Codex'in client ID'sini kullanma, kendi client ID'ni al

**İlk adım:**
1. Yukarıdaki Python kodunu dene
2. `codex login` yap
3. Token'ları oku ve ChatGPT plan tipini kontrol et
4. Başarılı olursa kendi CLI'na entegre et
