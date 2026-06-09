import socket
import asyncio
import re 
import json
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import asdict

from DataModels import Host, Port, Vulnerability 

from core_engine import (
    resolve_target, 
    SynScanner, 
    AsyncConnectScanner,
    ServiceDetector, 
    has_elevated_privileges, 
    scapy_is_available,
    mitre_mappings_for_result,
    WebRequestController,
    AdaptivePacer,
    BanSignalAnalyzer,
    DecoyInjector,
    build_pool_direct,
    build_pool_tor_only,
    write_executive_report,
    REPORT_PREFIX           
)
from api_client import NISTClient 

class DummyCveLookup:
    def __init__(self):
        self.enabled = True
        self.throttler = None  
        
    async def query(self, *args, **kwargs):
        return []
        
    async def aclose(self, *args, **kwargs):
        pass
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def __getattr__(self, name):
        async def _dummy_method(*args, **kwargs):
            return []
        return _dummy_method

class ScannerController:
    def __init__(self, target_ip: str, target_name: str = ""):
        self.target_ip = target_ip
        self.target_obj = resolve_target(self.target_ip)
        self.target_name = target_name or self.target_obj.original
        
        self.current_host = Host(
            ip_address=self.target_obj.address, 
            hostname=self.target_name
        ) 

    # YENİ: cve_enabled parametresi eklendi
    async def _map_results_to_objects(self, raw_results: dict, syn_info: dict, cve_enabled: bool = True, gui_log_func=None):
        nist = NISTClient() 
        api_tasks = []
        temp_ports = []

        for port_num, port_data in raw_results.items():
            raw_v = port_data.version
            clean_v = re.sub(r'^(SSH-2.0-|HTTP/1.1\s|Server:\s)', '', raw_v, flags=re.IGNORECASE)
            clean_v = clean_v.split('\n')[0].strip()
            
            port_data.mitre_attack = mitre_mappings_for_result(port_data)
            
            new_port = Port(
                number=port_num,
                protocol="TCP",
                state=port_data.state,
                service_name=port_data.service,
                service_version=clean_v,
                tls=port_data.tls,
                http_status=port_data.http_status,
                title=port_data.title,
                waf=port_data.waf,
                os_hint=syn_info.get(port_num, port_data.os_hint),
                tls_certificate=port_data.tls_certificate,
                mitre_attack=port_data.mitre_attack,
                notes=port_data.notes
            )
            
            if hasattr(port_data, 'sensitive_paths') and port_data.sensitive_paths:
                new_port.sensitive_paths = [{"path": p.path, "status": p.status, "size": p.size} for p in port_data.sensitive_paths]
            if hasattr(port_data, 'api_paths') and port_data.api_paths:
                new_port.api_paths = [{"path": p.path, "status": p.status, "size": p.size} for p in port_data.api_paths]
            if hasattr(port_data, 'security_headers'):
                new_port.security_headers = port_data.security_headers

            temp_ports.append(new_port)
            
            # YENİ: Arayüzden CVE kapatıldıysa API'ye istek atmaz
            if clean_v and cve_enabled and clean_v.lower() not in ["unknown", "open, no banner", "open, probe failed", "web probe failed"]:
                if gui_log_func: gui_log_func(f"[*] Port {port_num} ({clean_v}) için NIST veritabanı taranıyor...")
                api_tasks.append(nist.search_vulnerabilities(new_port.service_name, clean_v))
            else: 
                async def empty_task(): return []
                api_tasks.append(empty_task())

        if api_tasks:
            try:
                all_vulns_lists = await asyncio.gather(*api_tasks)
                for port_obj, vulns, port_num in zip(temp_ports, all_vulns_lists, raw_results.keys()):
                    port_obj.vulnerabilities.extend(vulns)
                    self.current_host.ports.append(port_obj)
                    try:
                        raw_results[port_num].cves = [
                            {"id": v.cve_id, "severity": v.severity, "description": v.description} for v in vulns
                        ]
                    except Exception:
                        pass
            except Exception as e:
                if gui_log_func: gui_log_func(f"[-] NIST API Eror: {str(e)}")

    def _save_reports(self, scan_results: dict, web_controller, scan_mode: str, roe_ref: str, gui_log_func=None):
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
            safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.target_obj.address)
            
            output_dir = Path("reports")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            json_path = output_dir / f"{REPORT_PREFIX}_{safe_target}_{timestamp}.json"
            md_path = output_dir / f"{REPORT_PREFIX}_{safe_target}_{timestamp}.executive.md"
            
            web_policy = web_controller.report_metadata() if hasattr(web_controller, 'report_metadata') else {}
            
            payload = {
                "scanner": "BlueScan Ultimate GUI",
                "version": "3.3",
                "target": asdict(self.target_obj),
                "timestamp_utc": timestamp,
                "scan_mode": scan_mode,
                "roe_ref": roe_ref or "GUI-Authorized",
                "web_policy": web_policy,
                "ports": [asdict(scan_results[port]) for port in sorted(scan_results)]
                
            }
            
            with json_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                
            write_executive_report(
                target=self.target_obj,
                results=scan_results,
                roe_ref=roe_ref or "GUI-Authorized",
                scan_mode=scan_mode,
                web_policy=web_policy,
                raw_report_path=json_path,
                output_path=md_path
            )
            
            if gui_log_func:
                gui_log_func("\n[+] Reports has been created succesfuly")
                gui_log_func(f"  -> Markdown: {md_path.resolve()}")
                
        except Exception as e:
            if gui_log_func: gui_log_func(f"[-]Report creation eror!: {str(e)}")

    async def execute_scan_pipeline(self, ports: list, scan_config: dict = None, gui_log_func=None):
        scan_config = scan_config or {}
        
        is_web_only = bool(scan_config.get("web_only"))
        use_tor = bool(scan_config.get("use_tor"))
        is_fast = bool(scan_config.get("fast_mode"))
        cve_enabled = bool(scan_config.get("cve_enabled", True))
        roe_ref = scan_config.get("roe_ref", "")
        skip_web_checks = bool(scan_config.get("skip_web_checks", False))
        tls_no_verify = bool(scan_config.get("tls_no_verify", False))
        user_agent = scan_config.get("user_agent", None)  
        fingerprint = scan_config.get("fingerprint", None)


        open_ports = []
        os_hints = {}
        scan_mode = "unknown"

        if not is_web_only:
            if has_elevated_privileges() and scapy_is_available():
                scan_mode = "syn-stealth"
                if gui_log_func: gui_log_func("[*] Elevated mode (SYN Stealth Scan) initiated...")
                scanner = SynScanner(target=self.target_obj, timeout=0.75 if is_fast else 1.5, retry=1, batch_size=1024 if is_fast else 512)
                open_ports = await asyncio.get_running_loop().run_in_executor(None, scanner.scan, ports)
                os_hints = scanner.os_hints
            else:
                scan_mode = "async-connect"
                if gui_log_func: gui_log_func("[*] Standart mod initiated...")
                scanner = AsyncConnectScanner(target=self.target_obj, concurrency=1000 if is_fast else 500, timeout=0.75 if is_fast else 1.5)
                open_ports = await scanner.scan(ports)
            
            if not open_ports:
                if gui_log_func: gui_log_func("[-] No open ports!")
                return self.current_host 
            
            if gui_log_func: gui_log_func(f"[+] {len(open_ports)} open ports had been found...")
        else:
            scan_mode = "web-only"
            if gui_log_func: gui_log_func("[*] Web-Only mode active, skipping port discovery...")
            open_ports = ports

        if use_tor:
            if gui_log_func: gui_log_func("[*] Tor is active, masking IP adress...")
            egress_pool = build_pool_tor_only()
        else:
            egress_pool = build_pool_direct()

        base_delay = 0.0 if is_fast else 0.5
        pacer = AdaptivePacer(base_delay=base_delay, sensitive_delay=base_delay, max_global_rate=6000 if is_fast else 50)
        ban_analyzer = BanSignalAnalyzer(stop_statuses={429}, soft_threshold=10)
        decoy = DecoyInjector(rate=0.0, paths=[])
        verify_tls_flag = not tls_no_verify
        web_controller = WebRequestController(
            egress=egress_pool,
            pacer=pacer,
            ban_analyzer=ban_analyzer,
            decoy=decoy,
            verify_tls=verify_tls_flag,
            user_agent=user_agent,   
            fingerprint=fingerprint
        )

        detector = ServiceDetector(
            target=self.target_obj,
            concurrency=100 if is_fast else 50,
            timeout=1.0 if is_fast else 3.0,
            check_sensitive_paths=not skip_web_checks,
            cve_lookup=DummyCveLookup(),
            web_controller=web_controller,
            web_only=is_web_only,
            verify_tls=verify_tls_flag
        )
        
        try:
            scan_results = await detector.detect(open_ports)
            
            # YENİ: Arayüzden alınan cve_enabled parametresi paslanıyor
            await self._map_results_to_objects(scan_results, os_hints, cve_enabled, gui_log_func)
            
            # YENİ: Arayüzden alınan roe_ref paslanıyor
            self._save_reports(scan_results, web_controller, scan_mode, roe_ref, gui_log_func)
            
            if use_tor and web_controller.block_events and gui_log_func:
                gui_log_func(f"[!] {len(web_controller.block_events)} request were blocked by WAF.")
                
        except Exception as e:
            if gui_log_func: gui_log_func(f"\n[-] Critical eror: {str(e)}")
            if gui_log_func: gui_log_func(traceback.format_exc())
            
        finally:
            await web_controller.aclose()
            
        return self.current_host