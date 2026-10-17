import ipaddress
import json
import time
from pathlib import Path
from urllib.parse import urljoin

import requests

from modules.settings import get_settings
from providers.base import BaseProvider, ProviderInfo, ProviderError


class RDAPError(Exception):
    """Fallo al consultar RDAP (bootstrap, red, rate limit, respuesta inválida)."""


class RDAPLookup(BaseProvider):
    INFO = ProviderInfo(
        name="RDAP (WHOIS moderno)",
        requires_api_key=False,
        is_free=True,
        api_key_env_var=None,
        description="WHOIS moderno - informacion de registro de IPs (estandar público)"
    )

    BOOTSTRAP_URLS = {4: "https://data.iana.org/rdap/ipv4.json", 6: "https://data.iana.org/rdap/ipv6.json"}
    BOOTSTRAP_TTL = 7 * 86400
    CACHE_DIR = Path.home() / ".cache" / "atalaya-recon"
    TIMEOUT = 15
    MIN_INTERVAL = 0.5
    MAX_REDIRECTS = 3
    _last_call = 0.0

    def __init__(self, ip_address):
        super().__init__()
        self.logger = get_settings().setup_logger()
        ip = ipaddress.ip_address(str(ip_address).strip())  # ValueError si no es una IP
        if not ip.is_global:
            raise RDAPError(f"{ip} no es una IP pública; no está en ningún registro RDAP")
        self._ip = ip
        self.ip_address = str(ip)
        self.server = None

    def is_configured(self) -> bool:
        return True

    # ------------------------------------------------------------------ HTTP
    def _get(self, url, accept="application/json"):
        """GET con espera mínima, timeout y redirecciones manuales (máx. 3, siempre HTTPS)."""
        wait = self.MIN_INTERVAL - (time.monotonic() - RDAPLookup._last_call)
        if wait > 0:
            time.sleep(wait)
        RDAPLookup._last_call = time.monotonic()

        headers = {"Accept": accept, "User-Agent": "atalaya-recon"}
        for _ in range(self.MAX_REDIRECTS + 1):
            try:
                response = requests.get(url, headers=headers, timeout=self.TIMEOUT, allow_redirects=False)
            except requests.exceptions.RequestException as e:
                raise RDAPError(f"Error de red consultando RDAP ({type(e).__name__})") from None
            if response.status_code in (301, 302, 303, 307, 308):
                url = urljoin(url, response.headers.get("Location", ""))
                if not url.startswith("https://"):
                    raise RDAPError("Redirección a un destino no HTTPS: se descarta")
                continue
            return response
        raise RDAPError("Demasiadas redirecciones")

    # ------------------------------------------------------------- bootstrap
    def _load_bootstrap(self):
        version = self._ip.version
        cache_file = self.CACHE_DIR / f"rdap_bootstrap_ipv{version}.json"
        try:
            if time.time() - cache_file.stat().st_mtime < self.BOOTSTRAP_TTL:
                return json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass  # sin caché o caché corrupta: se vuelve a descargar

        response = self._get(self.BOOTSTRAP_URLS[version])
        if not response.ok:
            raise RDAPError(f"No pude descargar el bootstrap de IANA (HTTP {response.status_code})")
        try:
            data = response.json()
        except ValueError:
            raise RDAPError("El bootstrap de IANA no es JSON válido") from None
        try:
            self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            self.logger.debug("No se pudo guardar la caché del bootstrap")
        return data

    def _find_server(self):
        """Prefijo más específico que contiene la IP -> URL base del RDAP autorizado."""
        best_len, best_url = -1, None
        for prefixes, urls in self._load_bootstrap().get("services", []):
            https = [u for u in urls if u.startswith("https://")]
            if not https:
                continue
            for prefix in prefixes:
                try:
                    net = ipaddress.ip_network(prefix)
                except ValueError:
                    continue
                if net.version == self._ip.version and self._ip in net and net.prefixlen > best_len:
                    best_len, best_url = net.prefixlen, https[0]
        if best_url is None:
            raise RDAPError(f"IANA no indica ningún servidor RDAP para {self.ip_address}")
        return best_url if best_url.endswith("/") else best_url + "/"

    # ------------------------------------------------------------- consultas
    def get_ip_info(self):
        base = self._find_server()
        self.server = base
        self.logger.debug(f"Consultando {self.ip_address} en {base}")
        response = self._get(f"{base}ip/{self.ip_address}", accept="application/rdap+json")
        if response.status_code == 404:
            return None
        if response.status_code == 429:
            raise RDAPError("Rate limit del servidor RDAP (429): espera un momento y reintenta")
        if not response.ok:
            raise RDAPError(f"El servidor RDAP respondió HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError:
            raise RDAPError("El servidor RDAP devolvió una respuesta que no es JSON") from None

    # --------------------------------------------------------------- resumen
    @staticmethod
    def _clean(value, limit=200):
        """Los registros los escribe cada titular: se quitan caracteres de control y se acota el largo."""
        text = "".join(ch if ch.isprintable() else " " for ch in str(value if value is not None else ""))
        return " ".join(text.split())[:limit]

    @staticmethod
    def _walk(entities):
        """Recorre entidades y sus entidades anidadas (el contacto de abuso suele ir dentro de la organización)."""
        for entity in entities or []:
            yield entity
            yield from RDAPLookup._walk(entity.get("entities"))

    @staticmethod
    def _vcard(entity):
        fields = {}
        card = entity.get("vcardArray")
        if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
            for item in card[1]:
                if isinstance(item, list) and len(item) >= 4:
                    fields.setdefault(item[0], item[3])
        org = fields.get("org")
        if isinstance(org, list):
            org = " ".join(str(o) for o in org)
        email = fields.get("email")
        return {"name": fields.get("fn") or org, "email": email if isinstance(email, str) else None}

    @staticmethod
    def summarize(info):
        if not info:
            return None
        clean = RDAPLookup._clean

        owners, abuse_emails = [], []
        for entity in RDAPLookup._walk(info.get("entities")):
            roles = entity.get("roles") or []
            card = RDAPLookup._vcard(entity)
            if "abuse" in roles and card["email"]:
                email = clean(card["email"], 120)
                if email not in abuse_emails:
                    abuse_emails.append(email)
            if ("registrant" in roles or "administrative" in roles) and card["name"]:
                owner = clean(card["name"], 120)
                if owner not in owners:
                    owners.append(owner)

        events = {}
        for ev in info.get("events") or []:
            if ev.get("eventAction") and ev.get("eventDate"):
                events.setdefault(ev["eventAction"], ev["eventDate"])

        cidrs = []
        for c in info.get("cidr0_cidrs") or []:
            prefix = c.get("v4prefix") or c.get("v6prefix")
            if prefix is not None and c.get("length") is not None:
                cidrs.append(f"{prefix}/{c['length']}")

        remarks = []
        for remark in info.get("remarks") or []:
            for line in (remark.get("description") or [])[:2]:
                remarks.append(clean(line))

        return {
            "ip_range": [info.get("startAddress"), info.get("endAddress")],
            "cidrs": cidrs,
            "name": clean(info.get("name"), 120),
            "handle": clean(info.get("handle"), 80),
            "type": clean(info.get("type"), 80),
            "country": clean(info.get("country"), 10),
            "status": info.get("status") or [],
            "owners": owners,
            "abuse_emails": abuse_emails,
            "registered": events.get("registration"),
            "last_changed": events.get("last changed"),
            "whois_server": clean(info.get("port43"), 80),
            "remarks": remarks[:3],
        }