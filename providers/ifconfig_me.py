import requests
from modules.settings import get_settings
from providers.base import BaseProvider, ProviderInfo


class IfconfigMe(BaseProvider):
    INFO = ProviderInfo(
        name="ifconfig.me",
        requires_api_key=False,
        is_free=True,
        api_key_env_var=None,
        description="Informacion de interfaz de red"
    )

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address
        self.url_base = f"https://ifconfig.me"
        self.logger = get_settings().setup_logger()

    def is_configured(self) -> bool:
        return True

    def get_ip_info(self):
        try:
            self.logger.debug(f"Retrieving information for IP {self.ip_address}")
            response = requests.get(f"{self.url_base}/all.json")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error retrieving IP information: {e}")
            return None
