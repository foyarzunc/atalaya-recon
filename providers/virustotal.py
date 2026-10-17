import requests
from modules.settings import get_settings
from providers.base import BaseProvider, ProviderInfo, ProviderError
import base64


class VirusTotal(BaseProvider):
    INFO = ProviderInfo(
        name="VirusTotal",
        requires_api_key=True,
        is_free=True,
        api_key_env_var="APIKEY_IP_VIRUS_TOTAL",
        description="Análisis de reputacion de IPs, URLs y archivos"
    )

    def __init__(self, ip_search=None):
        super().__init__()
        if ip_search is None:
            raise ValueError("IP address must be provided")
        self.ip_search = ip_search
        self.logger = get_settings().setup_logger()
        self.api_key = get_settings().APIKEY_IP_VIRUS_TOTAL
        self.base_url = "https://www.virustotal.com/api/v3"

    def is_configured(self) -> bool:
        return self._is_valid_api_key(self.api_key)

    def check_ip(self):
        self.check_configuration()
        url = f"{self.base_url}/ip_addresses/{self.ip_search}"
        headers = {
            "Accept": "application/json",
            "x-apikey": self.api_key
        }
        self.logger.info(f"Checking IP {self.ip_search} on VirusTotal...")
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.logger.info(f"IP {self.ip_search} not found in VirusTotal")
                return None
            elif response.status_code == 401:
                raise ProviderError(self.INFO, "API key rechazada (401)")
            elif response.status_code == 429:
                raise ProviderError(self.INFO, "Rate limit excedido (429)")
            else:
                self.logger.error(f"Failed to fetch data: {response.status_code} - {response.text}")
                return {"error": f"Failed to fetch data: {response.status_code}"}
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error: {e}")
            return None
