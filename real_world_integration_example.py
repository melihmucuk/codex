#!/usr/bin/env python3
"""
GERÇEK DÜNYA ÖRNEĞİ: Kendi CLI'nızdan Codex tokenlarını kullanma

Bu örnek, production-ready bir integration gösterir:
- Hata yönetimi
- Token refresh kontrolü
- Güvenli dosya okuma
- Multiple endpoint desteği
"""

import json
import base64
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import sys


class CodexTokenBridge:
    """Codex tokenlarını başka bir CLI'da kullanmak için köprü"""

    def __init__(self):
        self.auth_file = Path.home() / ".codex" / "auth.json"
        self._cached_creds: Optional[Dict[str, Any]] = None

    def is_codex_available(self) -> bool:
        """Codex auth.json var mı?"""
        return self.auth_file.exists()

    def get_credentials(self, force_reload: bool = False) -> Dict[str, Any]:
        """
        Codex credentials'larını al

        Returns:
            {
                'access_token': str,
                'account_id': str,
                'plan_type': str,  # 'plus', 'pro', 'free', etc.
                'email': str,
                'last_refresh': str,
            }

        Raises:
            FileNotFoundError: Codex auth.json bulunamadı
            ValueError: Token parse edilemedi
        """
        if self._cached_creds and not force_reload:
            return self._cached_creds

        if not self.is_codex_available():
            raise FileNotFoundError(
                "Codex auth.json bulunamadı.\n\n"
                "Çözüm seçenekleri:\n"
                "1. 'codex login' komutuyla giriş yapın\n"
                "2. Kendi OAuth implementasyonunuzu kullanın\n"
                "3. OPENAI_API_KEY environment variable'ı set edin"
            )

        try:
            with open(self.auth_file, 'r') as f:
                auth_data = json.load(f)

            tokens = auth_data.get("tokens", {})
            if not tokens:
                raise ValueError("auth.json'da token bulunamadı")

            id_token = tokens.get("id_token")
            access_token = tokens.get("access_token")

            if not access_token:
                raise ValueError("access_token eksik")

            # JWT'den metadata çıkar
            plan_type = self._extract_claim(id_token, "chatgpt_plan_type") if id_token else "unknown"
            email = self._extract_email(id_token) if id_token else None
            account_id = tokens.get("account_id")

            self._cached_creds = {
                "access_token": access_token,
                "account_id": account_id,
                "plan_type": plan_type,
                "email": email,
                "refresh_token": tokens.get("refresh_token"),
                "last_refresh": auth_data.get("last_refresh"),
            }

            return self._cached_creds

        except json.JSONDecodeError as e:
            raise ValueError(f"auth.json parse edilemedi: {e}")
        except Exception as e:
            raise ValueError(f"Credentials okunamadı: {e}")

    def _extract_claim(self, id_token: str, claim_name: str) -> Optional[str]:
        """JWT'den bir claim çıkar"""
        try:
            parts = id_token.split('.')
            if len(parts) != 3:
                return None

            # Base64 decode
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # chatgpt_plan_type auth claims içinde
            auth_claims = payload.get('https://api.openai.com/auth', {})
            return auth_claims.get(claim_name)

        except Exception:
            return None

    def _extract_email(self, id_token: str) -> Optional[str]:
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

        except Exception:
            return None

    def call_chatgpt_api(
        self,
        endpoint: str,
        method: str = 'GET',
        data: Optional[Dict] = None,
        base_url: str = "https://chatgpt.com/backend-api"
    ) -> Dict[str, Any]:
        """
        ChatGPT backend API'ye istek gönder

        Args:
            endpoint: API endpoint (örn: "conversations", "accounts/check")
            method: HTTP method ('GET', 'POST', etc.)
            data: POST data (optional)
            base_url: Base URL (override için)

        Returns:
            API response as dict

        Raises:
            requests.HTTPError: API isteği başarısız
        """
        try:
            import requests
        except ImportError:
            raise ImportError("requests kütüphanesi gerekli: pip install requests")

        creds = self.get_credentials()

        url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {creds['access_token']}",
        }

        # Account ID varsa ekle
        if creds.get('account_id'):
            headers["chatgpt-account-id"] = creds['account_id']

        # İstek gönder
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=30)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, json=data, timeout=30)
        else:
            raise ValueError(f"Desteklenmeyen HTTP method: {method}")

        # Response kontrol
        if response.status_code == 401:
            # Token expired - kullanıcıya bildir
            raise ValueError(
                "Token geçersiz veya süresi dolmuş.\n"
                "Lütfen 'codex login' ile yeniden giriş yapın."
            )
        elif response.status_code == 403:
            raise ValueError(
                "Bu işlem için yetkiniz yok.\n"
                "Account ID veya workspace ayarlarını kontrol edin."
            )

        response.raise_for_status()
        return response.json()


# ============================================================================
# CLI ENTEGRASYON ÖRNEKLERİ
# ============================================================================

def example_1_check_authentication():
    """Örnek 1: Authentication durumunu kontrol et"""
    print("=" * 60)
    print("Örnek 1: Authentication Kontrolü")
    print("=" * 60)

    bridge = CodexTokenBridge()

    if not bridge.is_codex_available():
        print("❌ Codex auth.json bulunamadı")
        print("   Lütfen 'codex login' yapın")
        return False

    try:
        creds = bridge.get_credentials()
        print(f"✅ Authentication başarılı!")
        print(f"   Email: {creds['email']}")
        print(f"   Plan: {creds['plan_type']}")
        print(f"   Account ID: {creds.get('account_id', 'N/A')}")
        return True

    except Exception as e:
        print(f"❌ Hata: {e}")
        return False


def example_2_list_conversations():
    """Örnek 2: ChatGPT conversation'larını listele"""
    print("\n" + "=" * 60)
    print("Örnek 2: Conversation Listesi")
    print("=" * 60)

    bridge = CodexTokenBridge()

    try:
        # API isteği
        response = bridge.call_chatgpt_api(
            endpoint="conversations?offset=0&limit=5"
        )

        conversations = response.get('items', [])
        print(f"✅ {len(conversations)} conversation bulundu:")

        for conv in conversations[:3]:
            title = conv.get('title', 'Untitled')
            conv_id = conv.get('id', 'unknown')
            print(f"   • {title[:50]} (ID: {conv_id})")

        return True

    except Exception as e:
        print(f"❌ API isteği başarısız: {e}")
        return False


def example_3_get_account_info():
    """Örnek 3: Account bilgilerini al"""
    print("\n" + "=" * 60)
    print("Örnek 3: Account Bilgileri")
    print("=" * 60)

    bridge = CodexTokenBridge()

    try:
        # Account check endpoint
        response = bridge.call_chatgpt_api(
            endpoint="accounts/check/v4-2023-04-27"
        )

        print("✅ Account bilgileri:")
        print(f"   Account: {response.get('account', {})}")

        # Plan bilgisi
        accounts = response.get('accounts', {})
        if accounts:
            for account_id, account_data in accounts.items():
                plan = account_data.get('account', {}).get('plan_type', 'unknown')
                print(f"   Plan Type: {plan}")

        return True

    except Exception as e:
        print(f"❌ API isteği başarısız: {e}")
        return False


def example_4_your_custom_cli():
    """Örnek 4: Kendi CLI'nızda kullanım"""
    print("\n" + "=" * 60)
    print("Örnek 4: Custom CLI Integration")
    print("=" * 60)

    # Kendi CLI'nızda böyle kullanabilirsiniz:

    bridge = CodexTokenBridge()

    # 1. Auth kontrolü
    if not bridge.is_codex_available():
        print("⚠️  Codex bulunamadı, alternatif auth yöntemine geçiliyor...")
        # Burada kendi OAuth flow'unuzu veya API key'inizi kullanın
        return False

    # 2. Credentials al
    try:
        creds = bridge.get_credentials()

        # 3. Plan bazlı features
        if creds['plan_type'] in ['plus', 'pro']:
            print("✅ Premium features aktif!")
            # Premium model kullan, daha fazla rate limit, etc.
        else:
            print("ℹ️  Free plan - sınırlı features")

        # 4. API çağrıları
        # Burada kendi CLI logic'iniz...

        print(f"✅ CLI başarıyla başlatıldı (User: {creds['email']})")
        return True

    except Exception as e:
        print(f"❌ Hata: {e}")
        return False


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Tüm örnekleri çalıştır"""

    print("\n🚀 Codex Token Bridge - Gerçek Dünya Örnekleri\n")

    # Tüm örnekleri çalıştır
    results = []

    results.append(("Auth Check", example_1_check_authentication()))

    if results[0][1]:  # Auth başarılıysa diğerlerini çalıştır
        results.append(("List Conversations", example_2_list_conversations()))
        results.append(("Account Info", example_3_get_account_info()))
        results.append(("Custom CLI", example_4_your_custom_cli()))

    # Özet
    print("\n" + "=" * 60)
    print("ÖZET")
    print("=" * 60)

    for name, success in results:
        status = "✅" if success else "❌"
        print(f"{status} {name}")

    # Sonuç
    all_success = all(result[1] for result in results)

    print("\n" + "=" * 60)
    if all_success:
        print("🎉 BAŞARILI! Codex tokenlarını kullanmak TAMAMEN MÜMKÜN!")
        print("\nENGELLER:")
        print("  ❌ API-level engel yok")
        print("  ❌ Client ID validation yok")
        print("  ❌ Origin check yok")
        print("  ✅ Sadece valid token gerekli")
        print("\n📝 Kullanım:")
        print("  1. ~/.codex/auth.json dosyasını oku")
        print("  2. access_token ve account_id çıkar")
        print("  3. Bearer token ile API'ye istek at")
        print("  4. Profit! 🚀")
    else:
        print("⚠️  Bazı testler başarısız oldu")
        print("   Muhtemelen 'codex login' yapmanız gerekiyor")

    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⛔ Kullanıcı tarafından durduruldu")
        sys.exit(0)
