# config.py
from functools import lru_cache
import logging
import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def check_env_file() -> None:
    env_path = Path(".env")
    env_example_path = Path(".env.example")
    
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
        print("  Then edit .env and add your API keys:")
        print()
        print("    APIKEY_SHODAN=your_shodan_api_key")
        print("    APIKEY_IP_VIRUS_TOTAL=your_virustotal_api_key")
        print("    APIKEY_OTX=your_alienvault_otx_api_key")
        print("    APIKEY_IP_ABUSE_DB=your_abuseipdb_api_key")
        print()
        print("  Note: Some providers work without API keys (RDAP, ip-api, ifconfig.me)")
        print()
        raise SystemExit(1)


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