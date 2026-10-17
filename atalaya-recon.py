#!/usr/bin/env python3
import argparse
import json
import logging
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from modules.nmap_mod import nmap_mod, ScanMode
from modules.settings import get_settings
from providers.base import ProviderError
from providers.shodan import Shodan
from providers.virustotal import VirusTotal
from providers.alienvault_otx import AlienVaultOTX
from providers.ip_abuse_db import IPAbuseDB
from providers.rdap_lookup import RDAPLookup
from providers.ip_api_geolocation import IPAPIGeolocation
from providers.ifconfig_me import IfconfigMe


RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
MAGENTA = "\033[35m"


def print_banner() -> None:
    banner = f"""
{CYAN}
    ╔═══════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                   ║
    ║  {BOLD}{YELLOW}   ###    ########    ###    ##          ###    ##    ##    ###    {CYAN}              ║
    ║  {BOLD}{YELLOW}  ## ##      ##      ## ##   ##         ## ##    ##  ##    ## ##   {CYAN}              ║
    ║  {BOLD}{YELLOW} ##   ##     ##     ##   ##  ##        ##   ##    ####    ##   ##  {CYAN}              ║
    ║  {BOLD}{YELLOW}##     ##    ##    ##     ## ##       ##     ##    ##    ##     ## {CYAN}              ║
    ║  {BOLD}{YELLOW}#########    ##    ######### ##       #########    ##    ######### {CYAN}              ║
    ║  {BOLD}{YELLOW}##     ##    ##    ##     ## ##       ##     ##    ##    ##     ## {CYAN}              ║
    ║  {BOLD}{YELLOW}##     ##    ##    ##     ## ######## ##     ##    ##    ##     ## {CYAN}              ║
    ║                                                                                   ║   
    ║  {BOLD}{GREEN}  ########  ########  ######   #######  ##    ## {CYAN}                                ║
    ║  {BOLD}{GREEN}  ##     ## ##       ##    ## ##     ## ###   ## {CYAN}                                ║
    ║  {BOLD}{GREEN}  ##     ## ##       ##       ##     ## ####  ## {CYAN}                                ║
    ║  {BOLD}{GREEN}  ########  ######   ##       ##     ## ## ## ## {CYAN}                                ║
    ║  {BOLD}{GREEN}  ##   ##   ##       ##       ##     ## ##  #### {CYAN}                                ║
    ║  {BOLD}{GREEN}  ##    ##  ##       ##    ## ##     ## ##   ### {CYAN}                                ║
    ║  {BOLD}{GREEN}  ##     ## ########  ######   #######  ##    ## {CYAN}                                ║
    ║                                                                                   ║
    ║  {BOLD}{MAGENTA}  OSINT Reconnaissance Tool - Gather IP intelligence with multiple providers{CYAN}     ║
    ║                                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════════════════════╝
{RESET}
"""
    print(banner)


AVAILABLE_PROVIDERS = {
    "shodan": {
        "class": Shodan,
        "description": "Shodan search engine - devices and vulnerabilities",
        "target_based": True,
    },
    "virustotal": {
        "class": VirusTotal,
        "description": "VirusTotal - IP/URL reputation analysis",
        "target_based": True,
    },
    "alienvault": {
        "class": AlienVaultOTX,
        "description": "AlienVault OTX - collaborative threat intelligence",
        "target_based": True,
    },
    "abuseipdb": {
        "class": IPAbuseDB,
        "description": "AbuseIPDB - malicious IP reports",
        "target_based": True,
    },
    "rdap": {
        "class": RDAPLookup,
        "description": "RDAP/WHOIS - IP registration info",
        "target_based": True,
    },
    "geolocation": {
        "class": IPAPIGeolocation,
        "description": "IP-API - geolocation data",
        "target_based": True,
    },
    "ifconfig": {
        "class": IfconfigMe,
        "description": "ifconfig.me - your public IP info (NOT target)",
        "target_based": False,
    },
}

NMAP_MODES = {
    "silent": ScanMode.SILENT,
    "aggressive": ScanMode.AGGRESSIVE,
    "basic": ScanMode.BASIC,
    "custom": ScanMode.CUSTOM,
}


def validate_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_nmap_ports(ports: str) -> bool:
    import re
    pattern = r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$'
    return bool(re.match(pattern, ports))


def center_text(text: str, width: int) -> str:
    return text.center(width)


def print_header(title: str, width: int = 80, char: str = "=") -> None:
    print()
    print(char * width)
    print(center_text(title, width))
    print(char * width)


def print_subheader(title: str, width: int = 80, char: str = "-") -> None:
    print()
    print(title)
    print(char * len(title))


def print_field(label: str, value: str, indent: int = 2) -> None:
    if value is None or value == "":
        value = "N/A"
    print(f"{' ' * indent}{label}: {value}")


def print_table(headers: list, rows: list, indent: int = 2) -> None:
    if not rows:
        print(f"{' ' * indent}No data available")
        return
    
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    header_line = " " * indent + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    separator = " " * indent + "-+-".join("-" * w for w in col_widths)
    
    print(header_line)
    print(separator)
    for row in rows:
        print(" " * indent + " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)))


def format_nmap_results(nmap_data: dict) -> None:
    if not nmap_data:
        print_field("Status", "No results")
        return
    
    for host, data in nmap_data.items():
        print_subheader(f"Host: {host}", width=76, char="-")
        print_field("State", data.get("state", "unknown"))
        print_field("Hostname", data.get("hostname", "N/A"))
        
        if data.get("os_matches"):
            print_subheader("OS Matches", char="-")
            for os in data["os_matches"][:3]:
                print_field("OS", f"{os['name']} (accuracy: {os['accuracy']}%)")
        
        protocols = data.get("protocols", {})
        if protocols:
            print_subheader("Open Ports", char="-")
            all_ports = []
            for proto, ports in protocols.items():
                for port, info in ports.items():
                    all_ports.append([
                        str(port),
                        proto.upper(),
                        info.get("service_name", ""),
                        info.get("product", ""),
                        info.get("version", ""),
                    ])
            
            if all_ports:
                print_table(
                    ["PORT", "PROTO", "SERVICE", "PRODUCT", "VERSION"],
                    all_ports[:20]
                )
                if len(all_ports) > 20:
                    print(f"\n  ... and {len(all_ports) - 20} more ports")


def format_geolocation(data: dict) -> None:
    if not data or data.get("status") != "success":
        print_field("Status", "Failed to retrieve geolocation")
        return
    
    print_field("Country", f"{data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
    print_field("Region", f"{data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})")
    print_field("City", data.get('city', 'N/A'))
    print_field("ZIP", data.get('zip', 'N/A'))
    print_field("Coordinates", f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
    print_field("ISP", data.get('isp', 'N/A'))
    print_field("Organization", data.get('org', 'N/A'))
    print_field("AS", data.get('as', 'N/A'))
    print_field("Timezone", data.get('timezone', 'N/A'))


def format_rdap(data: dict) -> None:
    if not data:
        print_field("Status", "No RDAP data available")
        return
    
    print_field("Name/Handle", f"{data.get('name', 'N/A')} ({data.get('handle', 'N/A')})")
    print_field("Type", data.get('type', 'N/A'))
    print_field("Country", data.get('country', 'N/A'))
    print_field("Status", ", ".join(data.get('status', [])) if data.get('status') else 'N/A')
    
    if data.get('ip_range'):
        print_field("IP Range", f"{data['ip_range'][0]} - {data['ip_range'][1]}")
    
    if data.get('cidrs'):
        print_field("CIDRs", ", ".join(data['cidrs']))
    
    if data.get('owners'):
        print_subheader("Owners", char="-")
        for owner in data['owners']:
            print_field("Owner", owner)
    
    if data.get('abuse_emails'):
        print_subheader("Abuse Contact", char="-")
        for email in data['abuse_emails']:
            print_field("Email", email)
    
    if data.get('registered'):
        print_field("Registered", data['registered'])
    if data.get('last_changed'):
        print_field("Last Changed", data['last_changed'])
    if data.get('whois_server'):
        print_field("WHOIS Server", data['whois_server'])
    
    if data.get('remarks'):
        print_subheader("Remarks", char="-")
        for remark in data['remarks'][:3]:
            print(f"  - {remark}")


def format_shodan(data: dict) -> None:
    if not data:
        print_field("Status", "No Shodan data available")
        return
    
    print_field("IP", data.get('ip', 'N/A'))
    print_field("Organization", data.get('org', 'N/A'))
    print_field("ISP", data.get('isp', 'N/A'))
    print_field("AS", data.get('asn', 'N/A'))
    print_field("Country", data.get('country', 'N/A'))
    print_field("City", data.get('city', 'N/A'))
    
    if data.get('hostnames'):
        print_subheader("Hostnames", char="-")
        for h in data['hostnames'][:5]:
            print_field("Hostname", h)
    
    if data.get('ports'):
        print_field("Open Ports", ", ".join(map(str, sorted(data['ports']))))
    
    if data.get('os'):
        print_field("OS", data['os'])
    
    if data.get('vulns'):
        print_subheader("Vulnerabilities", char="-")
        for v in data['vulns'][:10]:
            print_field("CVE", v)
    
    if data.get('services'):
        print_subheader("Services", char="-")
        service_rows = [[s['port'], s.get('product', ''), s.get('version', ''), s.get('banner_preview', '')[:40]] for s in data['services'][:10]]
        print_table(["PORT", "PRODUCT", "VERSION", "INFO"], service_rows)


def format_virustotal(data: dict) -> None:
    if not data:
        print_field("Status", "No VirusTotal data available")
        return
    
    if data.get('error'):
        print_field("Error", str(data['error']))
        return
    
    attrs = data.get('data', {}).get('attributes', {})
    
    stats = attrs.get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    
    print_field("IP", data.get('data', {}).get('id', 'N/A'))
    print_field("ASN", attrs.get('asn', 'N/A'))
    print_field("AS Owner", attrs.get('as_owner', 'N/A'))
    print_field("Country", attrs.get('country', 'N/A'))
    print_field("RIR", attrs.get('regional_internet_registry', 'N/A'))
    print_field("Network", attrs.get('network', 'N/A'))
    
    print()
    print_subheader("Reputation Score", char="-")
    reputation = attrs.get('reputation', 0)
    if reputation and reputation != 0:
        print_field("Score", str(reputation))
    else:
        print_field("Score", "No reputation data")
    
    print()
    print_subheader("Analysis Statistics", char="-")
    print_field("Malicious", str(malicious))
    print_field("Suspicious", str(suspicious))
    print_field("Harmless", str(harmless))
    print_field("Undetected", str(undetected))
    print_field("Timeout", str(stats.get('timeout', 0)))
    
    if attrs.get('last_https_certificate'):
        cert = attrs['last_https_certificate']
        subject = cert.get('subject', {})
        issuer = cert.get('issuer', {})
        
        print()
        print_subheader("SSL Certificate", char="-")
        print_field("Subject CN", subject.get('CN', 'N/A'))
        print_field("Issuer CN", issuer.get('CN', 'N/A'))
        
        validity = cert.get('validity', {})
        print_field("Valid From", validity.get('not_before', 'N/A'))
        print_field("Valid Until", validity.get('not_after', 'N/A'))
    
    if attrs.get('tags'):
        print()
        print_subheader("Tags", char="-")
        for tag in attrs['tags'][:10]:
            print_field("Tag", tag)
    
    if attrs.get('crowdsourced_context'):
        print()
        print_subheader("Threat Intelligence", char="-")
        for ctx in attrs['crowdsourced_context'][:5]:
            print_field("Title", ctx.get('title', 'N/A'))
            print_field("Severity", ctx.get('severity', 'N/A'))
            print_field("Source", ctx.get('source', 'N/A'))
            print()
    
    total_votes = attrs.get('total_votes', {})
    if total_votes:
        print_subheader("Community Votes", char="-")
        print_field("Harmless", str(total_votes.get('harmless', 0)))
        print_field("Malicious", str(total_votes.get('malicious', 0)))


def format_abuseipdb(data: dict) -> None:
    if not data:
        print_field("Status", "No AbuseIPDB data available")
        return
    
    if data.get('data'):
        d = data['data']
        print_field("IP", d.get('ipAddress', 'N/A'))
        print_field("Is Public", d.get('isPublic', 'N/A'))
        print_field("Is Whitelisted", d.get('isWhitelisted', 'N/A'))
        print_field("Abuse Confidence", f"{d.get('abuseConfidenceScore', 0)}%")
        print_field("Country Code", d.get('countryCode', 'N/A'))
        print_field("Usage Type", d.get('usageType', 'N/A'))
        print_field("ISP", d.get('isp', 'N/A'))
        print_field("Domain", d.get('domain', 'N/A'))
        print_field("Total Reports", str(d.get('totalReports', 0)))
        print_field("Num Distinct Users", str(d.get('numDistinctUsers', 0)))
        print_field("Last Reported At", d.get('lastReportedAt', 'N/A'))
    else:
        print_field("Status", "No abuse reports found")


def format_alienvault(data: dict) -> None:
    if not data:
        print_field("Status", "No AlienVault OTX data available")
        return
    
    print_field("ASN", data.get('asn', 'N/A'))
    print_field("Country", data.get('country', 'N/A'))
    print_field("City", data.get('city', 'N/A'))
    print_field("Pulse Count", str(data.get('pulse_count', 0)))
    print_field("Malware Count", str(data.get('malware_count', 0)))
    print_field("Passive DNS Count", str(data.get('passive_dns_count', 0)))
    
    if data.get('pulses'):
        print_subheader("Recent Pulses", char="-")
        for pulse in data['pulses'][:5]:
            print_field("Name", pulse.get('name', 'N/A'))
            if pulse.get('adversary'):
                print_field("Adversary", pulse.get('adversary'))
            tags = pulse.get('tags', [])
            if tags:
                print_field("Tags", ", ".join(tags[:5]))
            print()
    
    if data.get('passive_dns'):
        print_subheader("Passive DNS", char="-")
        dns_rows = [[r['hostname'], r.get('record_type', ''), r.get('first', ''), r.get('last', '')] for r in data['passive_dns'][:10]]
        print_table(["Hostname", "Type", "First Seen", "Last Seen"], dns_rows)


def format_ifconfig(data: dict) -> None:
    if not data:
        print_field("Status", "No ifconfig data available")
        return
    
    print_field("Your IP", data.get('ip_addr', 'N/A'))
    print_field("Port", data.get('port', 'N/A'))
    print_field("Method", data.get('method', 'N/A'))
    print_field("User Agent", data.get('user_agent', 'N/A'))
    if data.get('via'):
        print_field("Via", data.get('via'))
    if data.get('forwarded'):
        print_field("Forwarded", data.get('forwarded'))


FORMATTERS = {
    "geolocation": format_geolocation,
    "rdap": format_rdap,
    "shodan": format_shodan,
    "virustotal": format_virustotal,
    "abuseipdb": format_abuseipdb,
    "alienvault": format_alienvault,
    "ifconfig": format_ifconfig,
}


def run_nmap(target: str, mode: str, ports: Optional[str], scripts: Optional[str]) -> dict:
    mode_enum = NMAP_MODES.get(mode, ScanMode.BASIC)
    
    kwargs = {"mode": mode_enum}
    if ports:
        kwargs["ports"] = ports
    if scripts:
        kwargs["scripts"] = scripts.split(",")
    
    scanner = nmap_mod(target, **kwargs)
    scanner.scan()
    return scanner.get_full_details()


def run_target_provider(provider_name: str, target: str) -> Optional[dict]:
    info = AVAILABLE_PROVIDERS.get(provider_name)
    if not info or info["class"] is None:
        return None
    
    provider_class = info["class"]
    
    try:
        provider = provider_class(target)
        
        if not provider.is_configured():
            info_obj = provider.get_info()
            return {
                "status": "not_configured",
                "provider": provider_name,
                "requires_api_key": info_obj.requires_api_key,
                "api_key_env": info_obj.api_key_env_var,
                "is_free": info_obj.is_free,
                "description": info_obj.description,
                "message": f"Set {info_obj.api_key_env_var} in .env to enable",
            }
        
        if provider_name == "shodan":
            raw = provider.get_host_info()
            return {"status": "success", "data": provider.summarize(raw)} if raw else {"status": "no_data", "message": "No data found in Shodan"}
        elif provider_name == "alienvault":
            raw = provider.get_ip_info()
            return {"status": "success", "data": provider.summarize(raw)} if raw else {"status": "no_data", "message": "No data found in OTX"}
        elif provider_name == "rdap":
            raw = provider.get_ip_info()
            return {"status": "success", "data": provider.summarize(raw)} if raw else {"status": "no_data", "message": "No RDAP data found"}
        elif provider_name == "virustotal":
            raw = provider.check_ip()
            return {"status": "success", "data": raw} if raw else {"status": "no_data", "message": "No data found in VirusTotal"}
        elif provider_name == "abuseipdb":
            raw = provider.check_ip()
            return {"status": "success", "data": raw} if raw else {"status": "no_data", "message": "No abuse reports found"}
        elif provider_name == "geolocation":
            raw = provider.get_geolocation()
            return {"status": "success", "data": raw} if raw else {"status": "no_data", "message": "No geolocation data found"}
            
    except ProviderError as e:
        return {
            "status": "error",
            "error_type": "provider_error",
            "provider": provider_name,
            "message": str(e),
            "requires_api_key": e.requires_api_key,
            "is_free": e.is_free,
        }
    except Exception as e:
        return {
            "status": "error",
            "error_type": "unexpected",
            "provider": provider_name,
            "message": str(e),
        }
    
    return None


def run_user_ip_provider() -> Optional[dict]:
    try:
        provider = IfconfigMe("me")
        
        if not provider.is_configured():
            return {
                "status": "not_configured",
                "provider": "ifconfig",
                "description": "ifconfig.me - your public IP info",
            }
        
        raw = provider.get_ip_info()
        return {"status": "success", "data": raw} if raw else {"status": "no_data", "message": "Could not retrieve your IP"}
        
    except Exception as e:
        return {
            "status": "error",
            "provider": "ifconfig",
            "message": str(e),
        }


def list_providers() -> None:
    print()
    print("=" * 80)
    print(center_text("AVAILABLE PROVIDERS", 80))
    print("=" * 80)
    print()
    print("PROVIDER     TARGET            STATUS     DESCRIPTION")
    print("-" * 80)
    
    for name, info in AVAILABLE_PROVIDERS.items():
        target_flag = "TARGET IP" if info["target_based"] else "USER IP"
        
        try:
            prov = info["class"]("8.8.8.8")
            prov_info = prov.get_info()
            if not prov_info.requires_api_key:
                status = "OK"
            else:
                status = "OK" if prov.is_configured() else "NO KEY"
        except Exception:
            try:
                prov = info["class"]("8.8.8.8")
                prov_info = prov.get_info()
                if prov_info.requires_api_key:
                    status = "NO KEY"
                else:
                    status = "OK"
            except Exception:
                status = "NO KEY"
        
        print(f"{name:11} {target_flag:17} {status:10} {info['description']}")
    
    print()
    print("=" * 80)
    print(center_text("NMAP SCAN MODES", 80))
    print("=" * 80)
    print()
    print("MODE        DESCRIPTION")
    print("-" * 40)
    print("silent      Stealth scan - slow, quiet, minimal IDS detection")
    print("aggressive  Full scan - OS detection, version, scripts, vulns")
    print("basic      Balanced - good info at moderate speed")
    print("custom     User-defined ports and scripts")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="atalaya-recon",
        description="OSINT tool for IP reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 8.8.8.8 -p shodan rdap geolocation
  %(prog)s -t 1.1.1.1 --nmap-mode silent --nmap-ports 22,80,443
  %(prog)s -t 190.200.100.50 -p all
  %(prog)s -t 8.8.8.8 --nmap-mode aggressive -p shodan alienvault
  %(prog)s --list-providers
  %(prog)s --my-ip
        """
    )
    
    parser.add_argument(
        "--target", "-t",
        help="Target IP address to analyze"
    )
    
    parser.add_argument(
        "--providers", "-p",
        nargs="+",
        metavar="PROVIDER",
        help="Providers to use. Available: shodan | virustotal | alienvault | abuseipdb | rdap | geolocation | ifconfig | all"
    )
    
    parser.add_argument(
        "--nmap-mode",
        choices=["silent", "aggressive", "basic", "custom"],
        help="Nmap scan mode (REQUIRED if using nmap in --providers)"
    )
    
    parser.add_argument(
        "--nmap-ports",
        help="Ports for nmap scan (e.g., '22,80,443' or '1-1000')"
    )
    
    parser.add_argument(
        "--nmap-scripts",
        help="NSE scripts for nmap (comma-separated, e.g., 'vulners,discovery')"
    )
    
    parser.add_argument(
        "--my-ip",
        action="store_true",
        help="Get your public IP address information"
    )
    
    parser.add_argument(
        "--list-providers", "-l",
        action="store_true",
        help="List all available providers and exit"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="Output file (default: stdout)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format instead of formatted text"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress informational messages"
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    logger = get_settings().setup_logger()
    for handler in logger.handlers:
        handler.setLevel(100)
    
    if args.list_providers:
        logger.setLevel(logging.INFO)
        list_providers()
        return 0
    
    user_ip_result = run_user_ip_provider()
    
    if args.my_ip:
        if args.json:
            output = json.dumps({"provider": "ifconfig", "result": user_ip_result}, indent=2, default=str)
        else:
            print_header("YOUR PUBLIC IP INFORMATION")
            if user_ip_result and user_ip_result.get("status") == "success":
                format_ifconfig(user_ip_result.get("data"))
            else:
                print_field("Status", user_ip_result.get("message", "Failed") if user_ip_result else "Failed")
        return 0
    
    if not args.target:
        parser.error("--target is required (or use --my-ip or --list-providers)")
    
    if not validate_ip(args.target):
        print("Error: Invalid IP address")
        return 1
    
    if args.nmap_ports and not validate_nmap_ports(args.nmap_ports):
        print("Error: Invalid port format (use '22,80,443' or '1-1000')")
        return 1
    
    use_nmap = args.providers and "nmap" in args.providers
    if use_nmap and not args.nmap_mode:
        parser.error("--nmap-mode is required when using nmap in --providers")
    
    providers_to_run = []
    if args.providers:
        if "all" in args.providers:
            providers_to_run = [k for k in AVAILABLE_PROVIDERS.keys()]
        else:
            providers_to_run = [p for p in args.providers if p in AVAILABLE_PROVIDERS and p != "nmap"]
            if "nmap" in args.providers:
                use_nmap = True
    else:
        use_nmap = True
        if not args.nmap_mode:
            args.nmap_mode = "basic"
    
    nmap_result = None
    provider_results = {}
    
    if use_nmap:
        try:
            nmap_result = run_nmap(
                args.target,
                args.nmap_mode,
                args.nmap_ports,
                args.nmap_scripts
            )
        except Exception:
            nmap_result = None
    
    if providers_to_run:
        with ThreadPoolExecutor(max_workers=len(providers_to_run)) as executor:
            future_to_provider = {
                executor.submit(run_target_provider, provider, args.target): provider
                for provider in providers_to_run
            }
            for future in as_completed(future_to_provider):
                provider = future_to_provider[future]
                try:
                    result = future.result()
                    if result:
                        provider_results[provider] = result
                except Exception:
                    pass
    
    if args.json:
        output_data = {
            "user_ip": user_ip_result.get("data") if user_ip_result.get("status") == "success" else None,
            "target": args.target,
            "nmap": {
                "enabled": nmap_result is not None,
                "mode": args.nmap_mode,
                "ports": args.nmap_ports,
                "results": nmap_result,
            } if use_nmap else None,
            "providers": provider_results,
        }
        output = json.dumps(output_data, indent=2, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
        else:
            print(output)
        return 0
    
    print_header(f"ATALAYA-RECON: {args.target}")
    print()
    print_subheader("SOURCE IP (Your Public IP)", char="-")
    print("This is your public IP address (informational only)")
    print()
    if user_ip_result and user_ip_result.get("status") == "success":
        format_ifconfig(user_ip_result.get("data"))
    else:
        print_field("Status", user_ip_result.get("message", "Could not determine") if user_ip_result else "Could not determine")
    print()
    
    if use_nmap:
        print_subheader("NMAP SCAN RESULTS", char="-")
        print(f"Mode: {args.nmap_mode.upper()} | Ports: {args.nmap_ports or 'default'}")
        if nmap_result:
            format_nmap_results(nmap_result)
        else:
            print_field("Status", "Scan failed or no hosts found")
    
    for provider_name, result in provider_results.items():
        print_header(f"{provider_name.upper()} - {AVAILABLE_PROVIDERS[provider_name]['description']}")
        
        if result["status"] == "success":
            formatter = FORMATTERS.get(provider_name)
            if formatter:
                formatter(result.get("data"))
            else:
                print(json.dumps(result.get("data"), indent=2, default=str))
        elif result["status"] == "no_data":
            print_field("Status", result.get("message", "No data available"))
        elif result["status"] == "not_configured":
            print_field("Status", "Not configured")
            print_field("Description", result.get("description", ""))
            print_field("API Key", f"Set {result.get('api_key_env')} in .env")
            print_field("Pricing", "FREE" if result.get("is_free") else "PAID")
        elif result["status"] == "error":
            print_field("Error", result.get("message", "Unknown error"))
            if result.get("requires_api_key"):
                print_field("Note", "This provider requires an API key")
    
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
