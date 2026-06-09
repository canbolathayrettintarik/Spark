import aiohttp
import asyncio
import re
from DataModels import Vulnerability

# Yeni motordan gelen Throttler (Hız Sınırlayıcı) entegrasyonu
try:
    from asyncio_throttle import Throttler
except ImportError:
    Throttler = None

class NISTClient:
    # Yeni motorun gelişmiş servis eşleştirme sözlükleri
    CPE_PRODUCT_MAP = {
        "apache": ("apache", "http_server"),
        "apache httpd": ("apache", "http_server"),
        "apache tomcat": ("apache", "tomcat"),
        "nginx": ("nginx", "nginx"),
        "openssh": ("openbsd", "openssh"),
        "open ssh": ("openbsd", "openssh"),
        "microsoft-iis": ("microsoft", "iis"),
        "microsoft iis": ("microsoft", "iis"),
        "iis": ("microsoft", "iis"),
        "mysql": ("oracle", "mysql"),
        "mariadb": ("mariadb", "mariadb"),
        "postgresql": ("postgresql", "postgresql"),
        "proftpd": ("proftpd", "proftpd"),
        "vsftpd": ("vsftpd", "vsftpd"),
        "pure-ftpd": ("pureftpd", "pure-ftpd"),
    }

    CPE_SERVICE_PRODUCTS = {
        "http": frozenset({"apache", "apache httpd", "nginx", "microsoft-iis", "microsoft iis", "iis", "apache tomcat"}),
        "https": frozenset({"apache", "apache httpd", "nginx", "microsoft-iis", "microsoft iis", "iis", "apache tomcat"}),
        "ssh": frozenset({"openssh", "open ssh"}),
        "mysql": frozenset({"mysql", "mariadb"}),
        "postgresql": frozenset({"postgresql"}),
        "ftp": frozenset({"proftpd", "vsftpd", "pure-ftpd"}),
    }

    def __init__(self, api_key: str = None, concurrency: int = 3):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"apiKey": api_key} if api_key else {}
        self.semaphore = asyncio.Semaphore(concurrency)
        
        rate_limit = 2000 if api_key else 90
        self.throttler = Throttler(rate_limit=rate_limit, period=300) if Throttler else None

    def _query_from_version(self, service: str, version: str) -> str | None:
        """Yeni motorun gelişmiş CPE oluşturma algoritması (Regex Parsing)"""
        if not version or version.lower() in {"unknown", "filtered", "no response", "open, no banner", "open, probe failed"}:
            return None
        if version.startswith("<Binary Data:"):
            return None

        cleaned = re.sub(r"[\r\n].*", "", version).strip()
        cleaned = re.sub(r"\([^)]*\)", "", cleaned)
        cleaned = re.sub(r"[,;]+", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()

        if not cleaned:
            return None

        candidates = [
            r"(?P<product>[A-Za-z][A-Za-z0-9+_. -]+)/(?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
            r"(?P<product>OpenSSH)[-_](?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
            r"(?P<product>[A-Za-z][A-Za-z0-9+_. -]+)\s+(?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
        ]

        product_name = ""
        product_version = ""
        for pattern in candidates:
            match = re.search(pattern, cleaned, re.IGNORECASE)
            if match:
                product_name = re.sub(r"\s+", " ", match.group("product")).strip()
                product_version = match.group("version").strip()
                break

        if not product_name or not product_version:
            return None

        normalized = product_name.lower().replace("_", " ").replace("/", " ").strip()
        
        allowed_products = self.CPE_SERVICE_PRODUCTS.get(service.lower())
        if allowed_products is None or normalized not in allowed_products:
            return None

        mapped = self.CPE_PRODUCT_MAP.get(normalized)
        if mapped is None:
            return None

        vendor, product = mapped
        return f"cpe:2.3:a:{vendor}:{product}:{product_version}:*:*:*:*:*:*:*"

    async def search_vulnerabilities(self, service_name: str, version: str):
        """Dışarıdan çağrılan ana fonksiyon, CPE ve Fallback mantığını yönetir."""
        virtual_match = self._query_from_version(service_name, version)
        
        params = {"resultsPerPage": 5}
        
        
        if virtual_match:
            params["virtualMatchString"] = virtual_match
        else:
             
            query = f"{service_name} {version}".strip()
            if not query or query.lower() in {"unknown", "open, no banner"}:
                return []
            params["keywordSearch"] = query

        async with self.semaphore:
            try:
                if self.throttler:
                    async with self.throttler:
                        return await self._make_request(params)
                else:
                    return await self._make_request(params)
            except Exception as e:
                print(f"----API error: {e}")
                return []

    async def _make_request(self, params):
        async with aiohttp.ClientSession(headers=self.headers) as session:
            async with session.get(self.base_url, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                elif response.status == 403:
                    print(f"[!] API rate is reached... Waiting...")
                    await asyncio.sleep(6)  
                return []

    def _parse_response(self, data):
         
        vulnerabilities = []
        vulnerabilities_list = data.get('vulnerabilities', [])

        for item in vulnerabilities_list:
            cve_data = item.get('cve', {})
            metrics = cve_data.get('metrics', {})
            cvss_data = {}
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            
            vuln = Vulnerability(
                cve_id=cve_data.get('id', 'Unknown'),
                cvss_score=float(cvss_data.get('baseScore', 0.0)),
                severity=cvss_data.get('baseSeverity', 'UNKNOWN'),
                description=cve_data.get('descriptions', [{}])[0].get('value', 'No description')
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities