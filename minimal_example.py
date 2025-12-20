#!/usr/bin/env python3
"""
MINIMAL ÖRNEK: Codex tokenlarını başka bir CLI'dan kullanma

Bu 30 satırlık script, Codex tokenlarını kullanarak ChatGPT API'ye
istek gönderebileceğinizi kanıtlar.

Gereksinimler:
  1. Codex yüklü olmalı (codex login yapılmış)
  2. pip install requests

Kullanım:
  python3 minimal_example.py
"""

import json
from pathlib import Path

# 1. Codex auth.json'ı oku
auth_file = Path.home() / ".codex" / "auth.json"
auth_data = json.load(open(auth_file))
tokens = auth_data["tokens"]

access_token = tokens["access_token"]
account_id = tokens.get("account_id")

# 2. ChatGPT API'ye istek at
import requests

response = requests.get(
    "https://chatgpt.com/backend-api/conversations?offset=0&limit=5",
    headers={
        "Authorization": f"Bearer {access_token}",
        "chatgpt-account-id": account_id,
        "Content-Type": "application/json",
    }
)

# 3. Sonuç
print(f"Status: {response.status_code}")
if response.status_code == 200:
    print("✅ BAŞARILI! Conversation listesi alındı:")
    data = response.json()
    print(json.dumps(data, indent=2)[:500])
else:
    print(f"❌ Hata: {response.text}")
