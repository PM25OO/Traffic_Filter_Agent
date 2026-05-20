"""Interface to threat intelligence APIs."""

import os
import logging
from typing import Dict, Any, List
import requests
import requests_cache

logger = logging.getLogger(__name__)


class ThreatIntelInterface:
    """Interface to threat intelligence APIs with caching."""

    def __init__(self):
        # Setup cache with 1 hour TTL
        requests_cache.install_cache(
            'threat_intel_cache',
            backend='memory',
            expire_after=3600
        )

        # API keys from environment (optional)
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')

        logger.info("Threat intelligence interface initialized")

    def check_urlhaus(self, ip: str) -> Dict[str, Any]:
        """Check IP against URLhaus malware database (free, no key required).

        Args:
            ip: IP address to check

        Returns:
            Threat intelligence data

        Example:
            {
              "threat_found": True,
              "malware_families": ["emotet", "trickbot"],
              "first_seen": "2024-01-15",
              "reference": "https://urlhaus.abuse.ch/host/1.2.3.4/"
            }
        """
        try:
            url = "https://urlhaus-api.abuse.ch/v1/host/"
            data = {"host": ip}

            response = requests.post(url, data=data, timeout=10)
            response.raise_for_status()

            result = response.json()

            if result.get("query_status") == "ok":
                urls = result.get("urls", [])
                if urls:
                    # Extract unique malware families
                    malware_families = list(set(
                        url.get("threat", "unknown")
                        for url in urls
                        if url.get("threat")
                    ))

                    return {
                        "status": "success",
                        "source": "URLhaus",
                        "threat_found": True,
                        "ip": ip,
                        "malware_families": malware_families,
                        "url_count": len(urls),
                        "first_seen": urls[0].get("date_added") if urls else None,
                        "reference": f"https://urlhaus.abuse.ch/host/{ip}/"
                    }

            # No threat found
            return {
                "status": "success",
                "source": "URLhaus",
                "threat_found": False,
                "ip": ip
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"URLhaus API error: {e}")
            return {
                "status": "error",
                "error_type": "api_error",
                "message": str(e)
            }

    def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation on AbuseIPDB (requires API key).

        Args:
            ip: IP address to check

        Returns:
            IP reputation data

        Note: Requires ABUSEIPDB_API_KEY environment variable
        """
        if not self.abuseipdb_key:
            return {
                "status": "error",
                "error_type": "config",
                "message": "AbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY environment variable."
            }

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90"
            }

            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()

            result = response.json()
            data = result.get("data", {})

            return {
                "status": "success",
                "source": "AbuseIPDB",
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "threat_found": data.get("abuseConfidenceScore", 0) > 50
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB API error: {e}")
            return {
                "status": "error",
                "error_type": "api_error",
                "message": str(e)
            }

    def check_multiple_ips(
        self,
        ips: List[str],
        providers: List[str] = ["urlhaus"]
    ) -> Dict[str, Any]:
        """Check multiple IPs against threat intelligence providers.

        Args:
            ips: List of IP addresses
            providers: List of providers to use ("urlhaus", "abuseipdb")

        Returns:
            Combined threat intelligence results
        """
        results = []

        for ip in ips:
            ip_result = {"ip": ip, "checks": []}

            if "urlhaus" in providers:
                urlhaus_result = self.check_urlhaus(ip)
                ip_result["checks"].append(urlhaus_result)

            if "abuseipdb" in providers:
                abuseipdb_result = self.check_abuseipdb(ip)
                ip_result["checks"].append(abuseipdb_result)

            # Aggregate threat status
            threat_found = any(
                check.get("threat_found", False)
                for check in ip_result["checks"]
                if check.get("status") == "success"
            )
            ip_result["threat_found"] = threat_found

            results.append(ip_result)

        # Summary
        threat_count = sum(1 for r in results if r["threat_found"])

        return {
            "status": "success",
            "total_ips": len(ips),
            "threats_found": threat_count,
            "results": results
        }
