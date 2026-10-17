# config.py
from functools import lru_cache
import logging
import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


API_PROVIDER_LINKS = {
    "APIKEY_SHODAN": ("Shodan", "https://account.shodan.io/register"),
    "APIKEY_IP_VIRUS_TOTAL": ("VirusTotal", "https://www.virustotal.com/gui/join-us"),
    "APIKEY_OTX": ("AlienVault OTX", "https://otx.alienvault.com/api"),
    "APIKEY_IP_ABUSE_DB": ("AbuseIPDB", "https://www.abuseipdb.com/account/api"),
}


def check_env_file() -> None:
    env_path = Path(".env")
    
    if not env_path.exists():
        print()
        print("\033[91m" + "=" * 80)
        print("  ERROR: .env file not found")
        print("=" * 80 + "\033[0m")
        print()
        print("  Please create a .env file by copying .env.example:")
        print()
        print("    cp .env.example .env")
        print()
        print("  Then edit .env and add your API keys.")
        print()
        print("  API Keys are optional - some providers work without them.")
        print("  However, for full functionality, register at:")
        print()
        for key, (name, url) in API_PROVIDER_LINKS.items():
            print(f"    {name}: {url}")
        print()
        raise SystemExit(1)


def check_api_keys() -> None:
    env_path = Path(".env")
    if not env_path.exists():
        return
    
    missing_keys = []
    env_content = env_path.read_text()
    
    for key in API_PROVIDER_LINKS.keys():
        key_found = False
        for line in env_content.splitlines():
            line = line.strip()
            if line.startswith(f"{key}="):
                value = line.split("=", 1)[1].strip()
                if not value or value == "DEFINE_YOUR_DEFAULT_API_KEY_IN_DOTENV":
                    missing_keys.append(key)
                key_found = True
                break
        if not key_found:
            missing_keys.append(key)
    
    if missing_keys:
        print()
        print("\033[93m" + "=" * 80)
        print("  WARNING: Some API keys are not configured")
        print("=" * 80 + "\033[0m")
        print()
        print("  The following providers require API keys:")
        print()
        for key in missing_keys:
            name, url = API_PROVIDER_LINKS[key]
            print(f"    \033[94m{name}\033[0m: {url}")
        print()
        print("  Note: Some providers work without API keys (RDAP, ip-api, ifconfig.me)")
        print()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    APP_NAME: str
    APP_VERSION: str
    APP_DEBUG: bool = False
    APIKEY_IP_ABUSE_DB: str = 'DEFINE_YOUR_DEFAULT_API_KEY_IN_DOTENV'
    APIKEY_IP_VIRUS_TOTAL: str = 'DEFINE_YOUR_DEFAULT_API_KEY_IN_DOTENV'
    APIKEY_SHODAN: str = 'DEFINE_YOUR_DEFAULT_API_KEY_IN_DOTENV'
    APIKEY_OTX: str = 'DEFINE_YOUR_DEFAULT_API_KEY_IN_DOTENV'

    def setup_logger(self) -> logging.Logger:
        logger = logging.getLogger(self.APP_NAME)
        logger.setLevel(logging.DEBUG if self.APP_DEBUG else logging.INFO)

        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG if self.APP_DEBUG else logging.INFO)
            ch.setFormatter(
                logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )
            logger.addHandler(ch)

        return logger


@lru_cache
def get_settings() -> Settings:
    check_env_file()
    return Settings()


def verify_api_keys() -> None:
    check_api_keys()