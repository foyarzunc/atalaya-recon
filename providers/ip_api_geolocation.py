from modules.settings import get_settings
from providers.base import BaseProvider, ProviderInfo
import requests


class IPAPIGeolocation(BaseProvider):
    INFO = ProviderInfo(
        name="ip-api.com",
        requires_api_key=False,
        is_free=True,
        api_key_env_var=None,
        description="Geolocalización de IPs (gratis, límite de 45 req/min)"
    )

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address
        self.url_base = f"http://ip-api.com/json/{self.ip_address}"
        self.logger = get_settings().setup_logger()

    def is_configured(self) -> bool:
        return True

    def get_geolocation(self):
        try:
            self.logger.debug(f"Retrieving geolocation for IP {self.ip_address}")
            response = requests.get(self.url_base)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error retrieving geolocation for IP {self.ip_address}: {e}")
            return None
