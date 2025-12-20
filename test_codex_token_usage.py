#!/usr/bin/env python3
"""
Test script: Codex tokenlarını kullanarak ChatGPT API'ye istek gönderme
Bu script, başka bir CLI'ın Codex tokenlarını kullanabileceğini gösterir.
"""

import json
import base64
from pathlib import Path
import sys

def extract_plan_from_jwt(id_token):
    """JWT'den plan tipini çıkar"""
    try:
        parts = id_token.split('.')
        if len(parts) != 3:
            return None

        # Base64 padding ekle
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += '=' * padding

        # Decode
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        # Plan tipini çıkar
        auth_claims = payload.get('https://api.openai.com/auth', {})
        return auth_claims.get('chatgpt_plan_type', 'unknown')
    except Exception as e:
        print(f"JWT parse hatası: {e}")
        return None

def extract_email_from_jwt(id_token):
    """JWT'den email çıkar"""
    try:
        parts = id_token.split('.')
        if len(parts) != 3:
            return None

        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += '=' * padding

        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get('email')
    except Exception as e:
        print(f"Email parse hatası: {e}")
        return None

def read_codex_credentials():
    """Codex'in auth.json dosyasından credentials oku"""
    auth_file = Path.home() / ".codex" / "auth.json"

    if not auth_file.exists():
        print("❌ HATA: ~/.codex/auth.json bulunamadı")
        print("   Önce 'codex login' komutunu çalıştırın.")
        return None

    try:
        with open(auth_file, 'r') as f:
            auth_data = json.load(f)

        tokens = auth_data.get("tokens", {})

        if not tokens:
            print("❌ HATA: auth.json'da token bulunamadı")
            return None

        # Token bilgilerini çıkar
        id_token = tokens.get("id_token")
        access_token = tokens.get("access_token")
        account_id = tokens.get("account_id")

        if not all([id_token, access_token]):
            print("❌ HATA: Gerekli token'lar eksik")
            return None

        # Plan ve email bilgilerini JWT'den çıkar
        plan_type = extract_plan_from_jwt(id_token)
        email = extract_email_from_jwt(id_token)

        return {
            "access_token": access_token,
            "account_id": account_id,
            "plan_type": plan_type,
            "email": email,
            "id_token": id_token,
        }

    except json.JSONDecodeError as e:
        print(f"❌ HATA: auth.json parse edilemedi: {e}")
        return None
    except Exception as e:
        print(f"❌ HATA: {e}")
        return None

def test_chatgpt_api_request(creds):
    """ChatGPT API'ye test isteği gönder"""
    try:
        import requests
    except ImportError:
        print("❌ HATA: 'requests' kütüphanesi bulunamadı")
        print("   pip install requests")
        return False

    # ChatGPT backend API endpoint (conversations listesi)
    url = "https://chatgpt.com/backend-api/conversations?offset=0&limit=1"

    headers = {
        "Authorization": f"Bearer {creds['access_token']}",
        "Content-Type": "application/json",
    }

    # Account ID varsa ekle
    if creds.get('account_id'):
        headers["chatgpt-account-id"] = creds['account_id']

    print("\n🔄 ChatGPT API'ye istek gönderiliyor...")
    print(f"   URL: {url}")
    print(f"   Headers: Authorization: Bearer {creds['access_token'][:20]}...")
    if creds.get('account_id'):
        print(f"   Headers: chatgpt-account-id: {creds['account_id']}")

    try:
        response = requests.get(url, headers=headers, timeout=10)

        print(f"\n📡 Response Status: {response.status_code}")

        if response.status_code == 200:
            print("✅ BAŞARILI! API isteği çalıştı!")

            # Response'u parse et
            data = response.json()
            print(f"\n📊 Response Preview:")
            print(json.dumps(data, indent=2)[:500] + "...")

            return True

        elif response.status_code == 401:
            print("❌ HATA: Unauthorized (401)")
            print("   Token geçersiz veya süresi dolmuş olabilir.")
            print("   'codex login' ile yeniden giriş yapın.")
            return False

        elif response.status_code == 403:
            print("❌ HATA: Forbidden (403)")
            print("   Account ID geçersiz veya izin yok.")
            return False

        else:
            print(f"❌ HATA: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ Network hatası: {e}")
        return False

def main():
    print("=" * 60)
    print("Codex Token Kullanım Testi")
    print("Başka bir CLI'dan Codex tokenlarını kullanma")
    print("=" * 60)

    # 1. Codex credentials'ları oku
    print("\n1️⃣ Codex auth.json dosyası okunuyor...")
    creds = read_codex_credentials()

    if not creds:
        sys.exit(1)

    # 2. Credentials bilgilerini göster
    print("\n✅ Credentials başarıyla okundu!")
    print(f"   Email: {creds['email']}")
    print(f"   Plan: {creds['plan_type']}")
    print(f"   Account ID: {creds.get('account_id', 'N/A')}")
    print(f"   Access Token: {creds['access_token'][:30]}...")

    # 3. ChatGPT API'ye test isteği gönder
    print("\n2️⃣ ChatGPT API'ye test isteği gönderiliyor...")
    success = test_chatgpt_api_request(creds)

    # 4. Sonuç
    print("\n" + "=" * 60)
    if success:
        print("🎉 SONUÇ: Başka bir CLI'dan Codex tokenlarını kullanmak")
        print("           TAMAMEN MÜMKÜN!")
        print("\n💡 Engellemeler:")
        print("   ❌ Teknik engel YOK")
        print("   ❌ API-level engel YOK")
        print("   ⚠️  Sadece dosya okuma izni gerekli")
        print("\n📝 Kullanım:")
        print("   1. ~/.codex/auth.json dosyasını oku")
        print("   2. access_token ve account_id'yi çıkar")
        print("   3. ChatGPT API'ye Bearer token ile istek at")
        print("   4. İşlem tamamdır!")
    else:
        print("❌ SONUÇ: Test başarısız oldu")
        print("   Muhtemelen login gerekli veya token süresi dolmuş")
    print("=" * 60)

if __name__ == "__main__":
    main()
