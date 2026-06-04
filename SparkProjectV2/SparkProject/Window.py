import customtkinter as ctk
import asyncio
import threading
import queue
from Controllerv1 import ScannerController
import core_engine
import io
import contextlib
import sys
import re

class StdoutRedirector:
    def __init__(self, gui_log_func):
        self.gui_log_func = gui_log_func
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def write(self, message):
        if message.strip():
            clean_message = self.ansi_escape.sub('', message)
            self.gui_log_func(clean_message.strip())

    def flush(self):
        pass

class BlueScanGUI:
    def print_banner_to_gui(self):
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            core_engine.print_banner()  
        banner_text = f.getvalue()
        self.console.insert("end", banner_text + "\n")
    
    def __init__(self, root):
        self.root = root
        self.root.title("BlueScan v3.3 Ultimate")
        self.root.geometry("1100x750")
        ctk.set_appearance_mode("dark")
        
        self.update_queue = queue.Queue()
        self._build_ui()
        self._check_queue()

    def _build_ui(self):
        self.sidebar = ctk.CTkFrame(self.root, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        
        self.logo = ctk.CTkLabel(self.sidebar, text="CRIMSONWEB", font=("Urbanist", 22, "bold"), text_color="#deff9a")
        self.logo.pack(pady=(20, 10))

        self.roe_entry = ctk.CTkEntry(self.sidebar, placeholder_text="RoE Ref (Örn: BLD-001)", width=180)
        self.roe_entry.pack(pady=(0, 20), padx=20)
         
        self.scan_btn = ctk.CTkButton(self.sidebar, text="FULL SCAN (1-65k)", command=self.on_full_scan_clicked, fg_color="#1a1a1a", border_width=1, border_color="#deff9a")
        self.scan_btn.pack(pady=10, padx=20)

        self.top_ports_btn = ctk.CTkButton(self.sidebar, text="QUICK SCAN (Top 1000)", command=self.on_top_ports_clicked, fg_color="#2b2b2b", border_width=1, border_color="#55ff55")
        self.top_ports_btn.pack(pady=10, padx=20)

        self.custom_port_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Example: 80,443,8080", width=180)
        self.custom_port_entry.pack(pady=(20, 5), padx=20)
        self.custom_scan_btn = ctk.CTkButton(self.sidebar, text="CUSTOM SCAN", command=self.on_custom_scan_clicked, fg_color="#4a4a4a", hover_color="#2b2b2b")
        self.custom_scan_btn.pack(pady=5, padx=20)

        self.options_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.options_frame.pack(pady=20, padx=10, fill="x")

        # CVE Butonu buradan tamamen kaldırıldı
        self.chk_fast = ctk.CTkSwitch(self.options_frame, text="Fast Mode", font=("Urbanist", 12))
        self.chk_fast.pack(pady=5, anchor="w")

        self.chk_web_only = ctk.CTkSwitch(self.options_frame, text="Web-Only ", font=("Urbanist", 12))
        self.chk_web_only.pack(pady=5, anchor="w")

        self.chk_tor = ctk.CTkSwitch(self.options_frame, text="Tor Mode", font=("Urbanist", 12))
        self.chk_tor.pack(pady=5, anchor="w")

        self.chk_tls_no_verify = ctk.CTkSwitch(self.options_frame, text="Skip TLS verification", font=("Urbanist", 12))
        self.chk_tls_no_verify.pack(pady=5, anchor="w")

        self.chk_no_web_checks = ctk.CTkSwitch(self.options_frame, text="Skip Web Checks", font=("Urbanist", 12))
        self.chk_no_web_checks.pack(pady=5, anchor="w")

        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(side="right", expand=True, fill="both", padx=10, pady=10)
        
        self.entry = ctk.CTkEntry(self.main_frame, placeholder_text="Target IP Address or Domain (Example: scanme.nmap.org)", width=500)
        self.entry.pack(pady=20)
        
        self.progress = ctk.CTkProgressBar(self.main_frame, width=800)
        self.progress.pack(pady=10)
        self.progress.set(0)
        
        self.console = ctk.CTkTextbox(self.main_frame, width=850, height=500, font=("Azeret Mono", 13))
        self.console.pack(pady=10)

    def log(self, message):
        self.update_queue.put(("log", message))

    def set_buttons_state(self, state_str):
        self.scan_btn.configure(state=state_str)
        self.top_ports_btn.configure(state=state_str)
        self.custom_scan_btn.configure(state=state_str)
        self.roe_entry.configure(state=state_str)
        self.entry.configure(state=state_str)

    def _check_queue(self):
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                if msg_type == "log":
                    self.console.insert("end", data + "\n")
                    self.console.see("end")
                elif msg_type == "progress":
                    self.progress.set(data)
                elif msg_type == "state":
                    self.set_buttons_state(data) 
        except queue.Empty:
            pass
        self.root.after(100, self._check_queue)

    def on_full_scan_clicked(self):
        ports = list(range(1, 65000))
        self.start_scan_process(ports)

    def on_top_ports_clicked(self):
        try:
            if hasattr(core_engine, 'TOP_PORTS'):
                top_ports = core_engine.TOP_PORTS
            elif hasattr(core_engine, 'get_top_ports'):
                top_ports = core_engine.get_top_ports()
            else:
                self.log("[-] No top port data in core engine!")
                return
            self.start_scan_process(top_ports)
        except Exception as e:
            self.log(f"[-] Error accessing engine ports: {str(e)}")

    def on_custom_scan_clicked(self):
        raw_ports = self.custom_port_entry.get().strip()
        if not raw_ports:
            self.log("[-]Please enter port numbers in the box above 'Custom Scan' (e.g. 80,443)")
            return
        
        port_list = []
        try:
            for part in raw_ports.split(","):
                part = part.strip()
                if not part: continue
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(part))
            port_list = sorted(list(set(port_list))) 
        except ValueError:
            self.log("[-] Invalid port format! Use only numbers, commas, and hyphens.")
            return

        self.start_scan_process(port_list)
   
    def start_scan_process(self, port_list):
        target = self.entry.get().strip()
        roe = self.roe_entry.get().strip()

        if not target:
            self.log("[-]Error: Target IP/Domain is missing!")
            return
        
        if not roe:
            self.log("[-] LEGAL WARNING: RoE Reference is mandatory!")
            self.log("[-] Please enter your authorization reference in the 'RoE Ref' box on the left menu.")
            return
        
        self.update_queue.put(("state", "disabled"))
        self.console.delete("1.0", "end")
        self.print_banner_to_gui()
        
        thread = threading.Thread(target=self.run_scanner, args=(target, port_list))
        thread.daemon = True
        thread.start()

    def run_scanner(self, target, port_list):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        old_stdout = sys.stdout
        sys.stdout = StdoutRedirector(self.log)
        
        self.log(f"[*] Target: {target}")
        self.log(f"[*] RoE Reference: {self.roe_entry.get().strip()}")
        self.log(f"[*] Port Count: {len(port_list)} ports selected.")
        
        scan_config = {
            "web_only": self.chk_web_only.get(),
            "use_tor": self.chk_tor.get(),
            "fast_mode": self.chk_fast.get(),
            "roe_ref": self.roe_entry.get().strip(),
            "tls_no_verify": self.chk_tls_no_verify.get(),
            "skip_web_checks": self.chk_no_web_checks.get()
        }
        
        try:
            controller = ScannerController(target_ip=target)
            results = loop.run_until_complete(
                controller.execute_scan_pipeline(ports=port_list, scan_config=scan_config, gui_log_func=self.log)
            )
            
            self.log(f"\n[+] SUCCESS: Scan finished for {results.ip_address}")
            for p in results.ports:
                vulns = len(p.vulnerabilities)
                extra = f" | WAF: {p.waf}" if p.waf else ""
                self.log(f"-> {p.number}/{p.protocol} | {p.service_name} | {p.service_version}{extra} | [{vulns} Vulns]")

        except Exception as e:
            self.log(f"[-] Critical Error: {str(e)}")
        finally:
            sys.stdout = old_stdout
            self.update_queue.put(("state", "normal"))
            loop.close()

if __name__ == "__main__":
    root = ctk.CTk()
    app = BlueScanGUI(root)
    root.mainloop()