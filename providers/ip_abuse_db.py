from modules.settings import get_settings
from providers.base import BaseProvider, ProviderInfo, ProviderError
import requests


class IPAbuseDB(BaseProvider):
    INFO = ProviderInfo(
        name="AbuseIPDB",
        requires_api_key=True,
        is_free=True,
        api_key_env_var="APIKEY_IP_ABUSE_DB",
        description="Reporte de IPs maliciosas y abuso"
    )

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address
        self.api_key = get_settings().APIKEY_IP_ABUSE_DB
        self.logger = get_settings().setup_logger()
        self.url_base = "https://api.abuseipdb.com/api/v2/check"

    def is_configured(self) -> bool:
        return self._is_valid_api_key(self.api_key)

    def check_ip(self):
        self.check_configuration()
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        params = {
            'ipAddress': self.ip_address,
            'maxAgeInDays': 90
        }
        try:
            self.logger.debug(f"Checking IP {self.ip_address} against AbuseIPDB")
            response = requests.get(self.url_base, headers=headers, params=params)
            if response.status_code == 401:
                raise ProviderError(self.INFO, "API key rechazada (401)")
            elif response.status_code == 429:
                raise ProviderError(self.INFO, "Rate limit excedido (429)")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error checking IP {self.ip_address}: {e}")
            return None
