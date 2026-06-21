import requests
import json
import os

CONFIG_PATH = "config/user_config.json"

def get_api_key():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
            return config.get('api_keys', {}).get('abuseipdb', '')
    return ''

def check_ip_reputation(ip_address):
    api_key = get_api_key()
    if not api_key:
        return None # API Key belum diisi

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Key': api_key, 'Accept': 'application/json'}
    
    try:
        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data['data']['abuseConfidenceScore']
    except Exception as e:
        print(f"Error checking IP reputation: {e}")
    return 0