from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ProviderInfo:
    name: str
    requires_api_key: bool
    is_free: bool
    api_key_env_var: str
    description: str


class ProviderError(Exception):
    """Error relacionado con un provider (API key faltante, rate limit, etc)."""
    def __init__(self, provider_info: ProviderInfo, message: str):
        self.provider_info = provider_info
        free_text = "gratis" if provider_info.is_free else "de pago"
        key_text = f"API key required ({free_text})" if provider_info.requires_api_key else "No API key required"
        super().__init__(f"[{provider_info.name}] {key_text}: {message}")
        self.provider_name = provider_info.name
        self.requires_api_key = provider_info.requires_api_key
        self.is_free = provider_info.is_free


class BaseProvider(ABC):
    INFO: ProviderInfo

    def __init__(self):
        self.logger = None

    @abstractmethod
    def is_configured(self) -> bool:
        """Retorna True si el provider está configurado y listo para usar."""

    def check_configuration(self) -> None:
        """Lanza ProviderError si el provider no está configurado."""
        if not self.is_configured():
            raise ProviderError(self.INFO, "API key no configurada. Verifica tu archivo .env")

    def get_info(self) -> ProviderInfo:
        """Retorna información del provider."""
        return self.INFO

    @staticmethod
    def _is_valid_api_key(key: str) -> bool:
        if not key:
            return False
        placeholder = "DEFINE_YOUR_DEFAULT_API_KEY_IN_DOTENV"
        if placeholder in key:
            return False
        if len(key) < 10:
            return False
        return True
