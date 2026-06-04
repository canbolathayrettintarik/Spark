from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class Vulnerability:
    cve_id: str
    cvss_score: float
    severity: str   
    description: str
    reference_url: Optional[str] = None

@dataclass
class Port:
    number: int
    protocol: str  
    state: str      
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    
   
    tls: bool = False
    http_status: Optional[int] = None
    title: Optional[str] = None
    waf: Optional[str] = None
    os_hint: Optional[str] = None
    
     
    sensitive_paths: List[Dict[str, Any]] = field(default_factory=list)
    api_paths: List[Dict[str, Any]] = field(default_factory=list)
    security_headers: List[Dict[str, Any]] = field(default_factory=list)
    tls_certificate: Dict[str, Any] = field(default_factory=dict)
    mitre_attack: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
 
   
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

@dataclass
class Host:
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_info: Optional[str] = None
    ports: List[Port] = field(default_factory=list)
    
    def get_critical_vulnerabilities(self) -> List[Vulnerability]:
        
        critical_vulns = []
        for port in self.ports:
            for vuln in port.vulnerabilities:
                if vuln.cvss_score >= 7.0 or vuln.severity.upper() in ["CRITICAL", "HIGH"]:
                    critical_vulns.append(vuln)
        return critical_vulns