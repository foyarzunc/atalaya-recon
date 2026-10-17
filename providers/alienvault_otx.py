import time
import ipaddress
import requests

from modules.settings import get_settings
from providers.base import BaseProvider, ProviderInfo, ProviderError


class AlienVaultOTX(BaseProvider):
    INFO = ProviderInfo(
        name="AlienVault OTX",
        requires_api_key=True,
        is_free=True,
        api_key_env_var="APIKEY_OTX",
        description="Inteligencia colaborativa y pulsos de seguridad"
    )

    BASE_URL = "https://otx.alienvault.com/api/v1"
    SECTIONS = ("general", "reputation", "geo", "malware", "url_list", "passive_dns")
    DEFAULT_SECTIONS = ("general", "reputation", "malware", "passive_dns", "url_list")
    TIMEOUT = 15
    MIN_INTERVAL = 0.5
    TOP = 10
    _last_call = 0.0

    def __init__(self, ip_address):
        super().__init__()
        self.api_key = get_settings().APIKEY_OTX
        self.logger = get_settings().setup_logger()
        ip = ipaddress.ip_address(str(ip_address).strip())
        if not ip.is_global:
            raise ValueError(f"{ip} is not valid public IP")
        self.ip_address = str(ip)
        self.ip_type = "IPv6" if ip.version == 6 else "IPv4"

    def is_configured(self) -> bool:
        return self._is_valid_api_key(self.api_key)

    def get_section(self, section):
        self.check_configuration()
        if section not in self.SECTIONS:
            raise ValueError(f"sección inválida: {section!r} (válidas: {', '.join(self.SECTIONS)})")

        wait = self.MIN_INTERVAL - (time.monotonic() - AlienVaultOTX._last_call)
        if wait > 0:
            time.sleep(wait)
        AlienVaultOTX._last_call = time.monotonic()

        url = f"{self.BASE_URL}/indicators/{self.ip_type}/{self.ip_address}/{section}"
        self.logger.debug(f"Querying {self.ip_address} on OTX ({section})")
        try:
            response = requests.get(
                url, headers={"X-OTX-API-KEY": self.api_key, "Accept": "application/json"}, timeout=self.TIMEOUT
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error in Query OTX ({type(e).__name__})")
            return None

        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            self.logger.error(f"OTX reject API key (HTTP {response.status_code})")
            return None
        if response.status_code == 429:
            self.logger.error("Rate limit de OTX (429): wait a moment and try again...")
            return None
        if not response.ok:
            self.logger.error(f"OTX response HTTP {response.status_code}")
            return None
        try:
            return response.json()
        except ValueError:
            self.logger.error("OTX returned a non-JSON response")
            return None

    def get_ip_info(self, sections=None):
        result = {"ip": self.ip_address, "type": self.ip_type, "sections": {}, "errors": {}}
        for section in sections or self.DEFAULT_SECTIONS:
            try:
                result["sections"][section] = self.get_section(section)
            except Exception as e:
                result["errors"][section] = str(e)
        return result

    @staticmethod
    def _clean(value, limit=120):
        text = "".join(ch if ch.isprintable() else " " for ch in str(value if value is not None else ""))
        return " ".join(text.split())[:limit]

    @staticmethod
    def summarize(info):
        if not info:
            return None
        clean = AlienVaultOTX._clean
        top = AlienVaultOTX.TOP
        sections = info.get("sections", {})
        general = sections.get("general") or {}
        pulse_info = general.get("pulse_info") or {}

        pulses = []
        for pulse in (pulse_info.get("pulses") or [])[:top]:
            families = []
            for fam in pulse.get("malware_families") or []:
                families.append(clean(fam.get("display_name") or fam.get("id")) if isinstance(fam, dict) else clean(fam))
            pulses.append({
                "name": clean(pulse.get("name")),
                "author": clean(pulse.get("author_name")),
                "modified": pulse.get("modified"),
                "adversary": clean(pulse.get("adversary")) or None,
                "malware_families": families,
                "tags": [clean(t, 40) for t in (pulse.get("tags") or [])[:top]],
            })

        malware = sections.get("malware") or {}
        passive_dns = sections.get("passive_dns") or {}
        url_list = sections.get("url_list") or {}

        return {
            "ip": info.get("ip"),
            "asn": clean(general.get("asn")),
            "country": clean(general.get("country_name")),
            "city": clean(general.get("city")),
            "reputation": sections.get("reputation") or general.get("reputation"),
            "pulse_count": pulse_info.get("count", 0),
            "pulses": pulses,
            "malware_count": malware.get("count", 0),
            "malware_samples": [
                {"hash": clean(m.get("hash")), "detections": m.get("detections"), "date": m.get("datetime_int")}
                for m in (malware.get("data") or [])[:top]
            ],
            "passive_dns_count": passive_dns.get("count", 0),
            "passive_dns": [
                {
                    "hostname": clean(r.get("hostname")),
                    "first": r.get("first"),
                    "last": r.get("last"),
                    "record_type": r.get("record_type"),
                }
                for r in (passive_dns.get("passive_dns") or [])[:top]
            ],
            "url_count": url_list.get("full_size", len(url_list.get("url_list") or [])),
            "urls": [
                {"url": clean(u.get("url"), 200), "date": u.get("date"), "http_code": u.get("httpcode")}
                for u in (url_list.get("url_list") or [])[:top]
            ],
            "errors": info.get("errors", {}),
        }
