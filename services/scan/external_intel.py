import logging
import requests
from typing import List, Dict, Any

logger = logging.getLogger("scan.intel")

class ExternalIntelClient:
    def __init__(self, shodan_key: str = "", hibp_key: str = ""):
        self.shodan_key = shodan_key
        self.hibp_key = hibp_key

    def scan_shodan_ip(self, ip: str) -> Dict[str, Any]:
        """
        Queries Shodan API for open ports, banners, and exposed services on public IP.
        """
        if not self.shodan_key:
            # Safe simulated response for development
            return {
                "ip": ip,
                "open_ports": [80, 443, 22],
                "hostnames": ["gateway.tenant.shielddesk.io"],
                "vulnerabilities": ["CVE-2023-44487"],
                "source": "shodan_simulated",
            }

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json()
                return {
                    "ip": ip,
                    "open_ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "vulnerabilities": data.get("vulns", []),
                    "source": "shodan_live",
                }
        except Exception as e:
            logger.error(f"Shodan API error: {e}")

        return {"ip": ip, "open_ports": [], "error": "Query failed"}

    def check_hibp_breach(self, email: str) -> List[Dict[str, Any]]:
        """
        Queries HaveIBeenPwned API to check employee credentials exposure.
        """
        if not self.hibp_key:
            return [{
                "email": email,
                "breach_name": "LinkedIn 2016",
                "breach_date": "2016-05-18",
                "compromised_data": ["email_addresses", "passwords"],
                "source": "hibp_simulated",
            }]

        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {"hibp-api-key": self.hibp_key, "user-agent": "ShieldDesk-Scan-Service"}
            res = requests.get(url, headers=headers, timeout=8)
            if res.status_code == 200:
                return res.json()
        except Exception as e:
            logger.error(f"HIBP API error: {e}")

        return []
