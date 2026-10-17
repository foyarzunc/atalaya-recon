# config.py
from functools import lru_cache
import logging

from pydantic_settings import BaseSettings, SettingsConfigDict


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
    return Settings()