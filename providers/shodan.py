import requests
from modules.settings import get_settings
from providers.base import BaseProvider, ProviderInfo, ProviderError
import time


class Shodan(BaseProvider):
    INFO = ProviderInfo(
        name="Shodan",
        requires_api_key=True,
        is_free=True,
        api_key_env_var="APIKEY_SHODAN",
        description="Motor de búsqueda para dispositivos conectados a Internet"
    )

    BASE_URL = "https://api.shodan.io"
    TIMEOUT = 15
    MIN_INTERVAL = 1.0
    _last_call = 0.0

    def __init__(self, ip_address=None):
        super().__init__()
        self.api_key = get_settings().APIKEY_SHODAN
        self.logger = get_settings().setup_logger()
        self.ip_address = ip_address

    def is_configured(self) -> bool:
        return self._is_valid_api_key(self.api_key)

    def _get(self, path, **params):
        self.check_configuration()

        wait = self.MIN_INTERVAL - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

        params["key"] = self.api_key
        try:
            response = requests.get(f"{self.BASE_URL}{path}", params=params, timeout=self.TIMEOUT)
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error while querying Shodan: {e}")
            return None

        if response.status_code == 404:
            return None
        if response.status_code == 401:
            self.logger.error("Shodan API key rejected (401). Please check your API key.")
            return None
        if response.status_code in (402, 403):
            self.logger.error(f"Your plan or credits do not allow this query (HTTP {response.status_code})")
            return None
        if response.status_code == 429:
            self.logger.error("Rate limit of Shodan (429): maximum ~1 request/segundo")
            return None
        if not response.ok:
            self.logger.error(f"Shodan responded with HTTP {response.status_code}")
            return None
        try:
            return response.json()
        except ValueError:
            self.logger.error("Shodan returned a response that is not JSON")
            return None

    def get_host_info(self, history=False):
        if not self.is_configured():
            raise ProviderError(self.INFO, "API key no configurada")
        if self.ip_address is None:
            self.logger.error("This method requires an IP address to be set. Please provide an IP address when initializing the Shodan class.")
            return None
        self.logger.debug(f"Querying {self.ip_address} on Shodan")
        params = {"history": "true"} if history else {}
        return self._get(f"/shodan/host/{self.ip_address}", **params)

    def get_api_info(self):
        self.check_configuration()
        return self._get("/api-info")

    @staticmethod
    def _clean(text, limit=120):
        text = "".join(ch if ch.isprintable() else " " for ch in str(text or ""))
        return " ".join(text.split())[:limit]

    @staticmethod
    def summarize(host):
        if not host:
            return None
        services = []
        for banner in host.get("data", []) or []:
            service = {
                "port": banner.get("port"),
                "transport": banner.get("transport"),
                "module": (banner.get("_shodan") or {}).get("module"),
                "product": banner.get("product"),
                "version": banner.get("version"),
                "cpe": banner.get("cpe", []),
                "banner_preview": Shodan._clean(banner.get("data")),
            }
            cert = (banner.get("ssl") or {}).get("cert")
            if cert:
                service["tls"] = {
                    "subject_cn": (cert.get("subject") or {}).get("CN"),
                    "issuer_cn": (cert.get("issuer") or {}).get("CN"),
                    "expires": cert.get("expires"),
                    "expired": cert.get("expired"),
                }
            services.append(service)
        services.sort(key=lambda s: (s["port"] is None, s["port"]))

        vulns = host.get("vulns") or []
        if isinstance(vulns, dict):
            vulns = list(vulns)
        return {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "isp": host.get("isp"),
            "asn": host.get("asn"),
            "os": host.get("os"),
            "country": host.get("country_name"),
            "city": host.get("city"),
            "hostnames": host.get("hostnames", []),
            "domains": host.get("domains", []),
            "tags": host.get("tags", []),
            "ports": sorted(host.get("ports", [])),
            "vulns": sorted(vulns),
            "last_update": host.get("last_update"),
            "services": services,
        }
