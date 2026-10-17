from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import ipaddress
import nmap
import os

from modules.settings import get_settings


class ScanMode(Enum):
    SILENT = "silent"
    AGGRESSIVE = "aggressive"
    BASIC = "basic"
    CUSTOM = "custom"


@dataclass
class NmapPreset:
    name: str
    description: str
    timing: str
    scripts: list[str]
    scan_type: str
    detect_os: bool
    version_detection: bool
    ports: str
    extra_args: list[str] = field(default_factory=list)

    def to_args(self, is_root: bool) -> list[str]:
        args = [self.scan_type, f"-T{self.timing}"]
        
        if self.version_detection and is_root:
            args.append("-sV")
        elif self.version_detection:
            args.append("-sV")
            
        if self.detect_os and is_root:
            args.append("-O")
            
        if self.scripts:
            args.append(f"--script={','.join(self.scripts)}")
            
        if self.extra_args:
            args.extend(self.extra_args)
            
        return args


PRESETS = {
    ScanMode.SILENT: NmapPreset(
        name="silent",
        description="Stealth scan with IDS/IPS evasion - slow and quiet",
        timing="2",
        scripts=[],
        scan_type="-sS",
        detect_os=False,
        version_detection=False,
        ports="21,22,23,25,80,443,445,3306,3389,8080",
    ),
    ScanMode.AGGRESSIVE: NmapPreset(
        name="aggressive",
        description="Full scan with OS detection, version detection and all vulnerability scripts",
        timing="4",
        scripts=["vulners", "discovery", "safe", "vuln", "auth"],
        scan_type="-sS",
        detect_os=True,
        version_detection=True,
        ports="1-10000",
    ),
    ScanMode.BASIC: NmapPreset(
        name="basic",
        description="Standard scan - balanced between speed and info",
        timing="3",
        scripts=["default"],
        scan_type="-sS",
        detect_os=True,
        version_detection=True,
        ports="1-1000",
    ),
}


class NmapError(Exception):
    """Error durante escaneo con nmap."""


class nmap_mod:
    COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    TOP_100_PORTS = "1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,444,445,458,464,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,995,999,1000,1001,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1033,1034,1035,1036,1037,1038,1039,1040,1041,1043,1044,1045,1048,1049,1050,1053,1054,1056,1058,1059,1066,1069,1071,1074,1080,1081,1082,1083,1084,1085,1090,1095,1097,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1117,1119,1121,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1192,1198,1199,1201,1213,1216,1217,1233,1236,1244,1247,1248,1259,1272,1277,1287,1296,1300,1301,1309,1311,1322,1328,1334,1352,1367,1372,1376,1380,1386,1389,1393,1396,1400,1433,1434,1441,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1581,1589,1604,1605,1608,1612,1628,1631,1658,1666,1687,1688,1701,1717,1718,1719,1720,1721,1723,1725,1755,1761,1782,1801,1808,1812,1813,1814,1875,1900,1935,1947,1959,1964,1974,1984,1998,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2035,2038,2045,2046,2047,2048,2049,2065,2082,2083,2086,2087,2095,2096,2099,2100,2105,2106,2111,2119,2121,2126,2135,2144,2160,2161,2179,2190,2191,2196,2200,2222,2223,2251,2260,2288,2301,2323,2332,2343,2345,2365,2372,2377,2380,2399,2400,2492,2500,2525,2533,2547,2598,2600,2601,2604,2605,2607,2608,2638,2653,2664,2694,2717,2725,2809,2811,2869,2875,2909,2929,2955,2967,2968,2998,3000,3001,3003,3005,3006,3007,3009,3011,3013,3015,3017,3030,3031,3050,3052,3074,3105,3106,3115,3128,3150,3200,3217,3221,3260,3261,3268,3269,3283,3300,3306,3322,3323,3324,3333,3351,3367,3369,3371,3372,3389,3404,3478,3498,3541,3542,3551,3580,3632,3659,3689,3690,3703,3735,3744,3780,3784,3790,3800,3801,3804,3809,3814,3826,3827,3828,3851,3868,3872,3880,3890,3900,3945,3960,3962,3986,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4447,4448,4449,4550,4567,4661,4664,4711,4712,4713,4728,4730,4731,4738,4740,4750,4786,4800,4840,4843,4847,4899,4949,5000,5009,5051,5060,5080,5104,5108,5190,5200,5214,5221,5222,5225,5226,5280,5298,5357,5432,5433,5440,5500,5544,5555,5631,5632,5666,5672,5678,5718,5800,5801,5802,5803,5810,5811,5813,5815,5850,5858,5900,5901,5984,5985,5986,6000,6001,6002,6003,6004,6005,6010,6015,6050,6054,6100,6112,6543,6544,6588,6646,6660,6661,6662,6663,6664,6665,6666,6667,6668,6669,6697,6771,6779,6800,6905,6969,7000,7001,7002,7004,7005,7007,7010,7021,7070,7100,7199,7223,7272,7301,7306,7307,7328,7391,7400,7414,7421,7443,7474,7547,7548,7549,7648,7676,7743,7777,7778,7779,7801,7831,7871,8000,8001,8008,8009,8010,8021,8022,8030,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8100,8123,8161,8180,8181,8192,8200,8222,8243,8280,8281,8291,8333,8383,8400,8443,8444,8445,8500,8545,8585,8630,8686,8787,8800,8834,8880,8888,8899,8983,9000,9001,9002,9003,9009,9010,9042,9050,9051,9060,9080,9090,9091,9099,9100,9101,9102,9103,9110,9111,9150,9191,9200,9201,9279,9292,9390,9391,9392,9393,9394,9395,9396,9397,9398,9399,9443,9500,9530,9595,9600,9695,9800,9876,9877,9878,9898,9900,9943,9944,9968,9998,9999,10000,10001,10010,10050,10080,10081,10082,10110,10243,10250,10443,10554,10616,10628,10629,11001,11108,11110,11111,11211,12000,12345,12443,13000,13443,14000,14147,15000,16000,17000,17500,18000,18001,18002,18080,18081,18082,18091,18092,19000,19501,20000,20547,21000,22000,22222,22223,23000,23222,24000,25000,26000,27000,28000,29000,30000,31337,32000,32764,33333,34000,35000,36000,37000,38000,39000,40000,41000,42000,43000,44000,45000,46000,47000,48000,49000,50000,50030,50060,50070,50090,60000"
    FULL_PORTS = "1-65535"

    def __init__(self, host: str, **kwargs):
        self.logger = get_settings().setup_logger()
        self._validate_host(host)
        self.host = host
        self._is_root = os.getuid() == 0
        
        self.mode = kwargs.get("mode", ScanMode.BASIC)
        if isinstance(self.mode, str):
            self.mode = ScanMode(self.mode.lower())
            
        self.ports = kwargs.get("ports", None)
        self.custom_scripts = kwargs.get("scripts", None)
        self.custom_args = kwargs.get("extra_args", None)
        self.timing_override = kwargs.get("timing", None)
        
        if not self._is_root:
            self.logger.warning("Not running as root. OS detection disabled.")
        
        self.nm = nmap.PortScanner()
        self._last_results = {}
        
    def _validate_host(self, host: str) -> None:
        try:
            ipaddress.ip_address(host)
            return
        except ValueError:
            pass
        
        try:
            ipaddress.ip_network(host, strict=False)
            return
        except ValueError:
            pass
            
        if not host.replace(".", "").replace("-", "").isalnum():
            raise NmapError(f"Invalid host: {host}")

    def _get_preset(self) -> NmapPreset:
        if self.mode == ScanMode.CUSTOM:
            return self._build_custom_preset()
        
        preset = PRESETS.get(self.mode)
        if not preset:
            self.logger.warning(f"Unknown mode {self.mode}, using BASIC")
            preset = PRESETS[ScanMode.BASIC]
        
        if self.ports:
            preset.ports = self.ports
            
        return preset

    def _build_custom_preset(self) -> NmapPreset:
        timing = self.timing_override or "3"
        scripts = self.custom_scripts or []
        ports = self.ports or self.COMMON_PORTS
        
        extra = self.custom_args or []
        if isinstance(extra, str):
            extra = extra.split()
            
        return NmapPreset(
            name="custom",
            description="Custom scan configuration",
            timing=timing,
            scripts=scripts,
            scan_type="-sS",
            detect_os=self._is_root,
            version_detection=True,
            ports=ports,
            extra_args=extra,
        )

    def _build_args(self) -> list[str]:
        preset = self._get_preset()
        args = [preset.scan_type, f"-T{preset.timing}"]
        
        if preset.version_detection:
            args.append("-sV")
            
        if preset.detect_os and self._is_root:
            args.append("-O")
            
        if preset.scripts:
            script_list = ",".join(preset.scripts)
            args.append(f"--script={script_list}")
            
        if self.custom_args:
            extra = self.custom_args if isinstance(self.custom_args, list) else self.custom_args.split()
            args.extend(extra)
            
        return args

    def scan(self) -> list[str]:
        try:
            args = self._build_args()
            ports = self.ports or self._get_preset().ports
            
            cmd = f"nmap {' '.join(args)} -p{ports} {self.host}"
            self.logger.info(f"Running: {cmd}")
            
            self.nm.scan(self.host, ports, arguments=" ".join(args))
            hosts = self.nm.all_hosts()
            
            if not hosts:
                self.logger.warning(f"No hosts found for {self.host}")
                
            return hosts
            
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap error: {e}")
            raise NmapError(f"Nmap scan failed: {e}") from None
        except Exception as e:
            self.logger.error(f"Unexpected error during scan: {e}")
            raise NmapError(f"Scan failed: {e}") from None

    def get_full_details(self) -> dict:
        if not self.nm.all_hosts():
            return {}
            
        results = {}
        
        for host in self.nm.all_hosts():
            host_data = self.nm[host]
            
            host_info = {
                "hostname": host_data.hostname(),
                "state": host_data.state(),
                "addresses": host_data.get("addresses", {}),
                "os_matches": [],
                "protocols": {},
                "scan_mode": self.mode.value,
            }
            
            if "osmatch" in host_data and self._is_root:
                for osmatch in host_data["osmatch"][:5]:
                    host_info["os_matches"].append({
                        "name": osmatch.get("name", "Unknown"),
                        "accuracy": osmatch.get("accuracy", "0"),
                        "line": osmatch.get("line", ""),
                    })
            
            for proto in host_data.all_protocols():
                ports_info = host_data[proto]
                host_info["protocols"][proto] = {}
                
                sorted_ports = sorted(ports_info.keys())
                
                for port in sorted_ports:
                    port_data = ports_info[port]
                    
                    if port_data["state"] == "open":
                        port_entry = {
                            "state": port_data.get("state"),
                            "reason": port_data.get("reason"),
                            "service_name": port_data.get("name", ""),
                            "product": port_data.get("product", ""),
                            "version": port_data.get("version", ""),
                            "extrainfo": port_data.get("extrainfo", ""),
                            "cpe": port_data.get("cpe", ""),
                            "conf": port_data.get("conf", ""),
                        }
                        
                        if "script" in port_data:
                            port_entry["scripts"] = port_data["script"]
                            
                        host_info["protocols"][proto][port] = port_entry
                        
            results[host] = host_info
            
        self._last_results = results
        return results

    def quick_scan(self, ports: Optional[str] = None) -> list[str]:
        original_mode = self.mode
        original_ports = self.ports
        
        self.mode = ScanMode.SILENT
        self.ports = ports or self.COMMON_PORTS
        
        result = self.scan()
        
        self.mode = original_mode
        self.ports = original_ports
        
        return result

    def vuln_scan(self) -> dict:
        self.mode = ScanMode.AGGRESSIVE
        self.scan()
        return self.get_full_details()

    def get_open_ports_summary(self) -> dict:
        details = self.get_full_details()
        summary = {}
        
        for host, data in details.items():
            open_ports = []
            for proto, ports in data.get("protocols", {}).items():
                for port, info in ports.items():
                    open_ports.append({
                        "port": port,
                        "protocol": proto,
                        "service": info.get("service_name", ""),
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                    })
            summary[host] = {
                "state": data.get("state"),
                "open_ports": sorted(open_ports, key=lambda x: x["port"]),
                "total_open": len(open_ports),
            }
            
        return summary
