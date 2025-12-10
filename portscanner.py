# Professional Port Scanner with Educational Features
# FIXED: All constants now properly defined

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import time
from datetime import datetime
import os

# ===================================================================
# CONSTANTS - Edit these values to change scanner behavior
# ===================================================================
DEFAULT_TIMEOUT = 2          # Seconds to wait per port
MAX_PORT = 65535            # Maximum valid port number (FIXED!)
SCAN_DELAY = 0.05           # Small delay between ports to reduce CPU usage

# ===================================================================
# EDUCATIONAL: Port Knowledge Base
# ===================================================================
# Key: Port Number: ("Service Name", "Typical State", "Description")
PORT_KNOWLEDGE = {
    21: ("FTP", "CLOSED", "File Transfer - Insecure, rarely used"),
    22: ("SSH", "MAYBE OPEN", "Secure Shell - Open on Linux/Mac servers"),
    23: ("Telnet", "CLOSED", "Unsecure remote login - Should be disabled"),
    25: ("SMTP", "CLOSED", "Email sending - Only for mail servers"),
    53: ("DNS", "MAYBE OPEN", "Domain System - Open if running DNS server"),
    80: ("HTTP", "MAYBE OPEN", "Web traffic - Open if web server running"),
    110: ("POP3", "CLOSED", "Email receiving - Blocked by default"),
    135: ("Windows RPC", "MAYBE OPEN", "Windows services - Often open on Windows"),
    139: ("NetBIOS", "MAYBE OPEN", "Windows file sharing - Sometimes open"),
    143: ("IMAP", "CLOSED", "Email - Blocked unless mail server"),
    443: ("HTTPS", "MAYBE OPEN", "Secure web - Open if web server with SSL"),
    445: ("SMB", "MAYBE OPEN", "Windows file sharing - Common on LAN"),
    3306: ("MySQL", "CLOSED", "MySQL Database - For developers only"),
    3389: ("RDP", "MAYBE OPEN", "Remote Desktop - Open if remote access enabled"),
    5900: ("VNC", "CLOSED", "Remote control - Usually disabled"),
    8080: ("HTTP-ALT", "MAYBE OPEN", "Alternative web port - For testing/dev"),
    
    # Add more ports as you learn them...
    20: ("FTP-DATA", "CLOSED", "File Transfer Data"),
    67: ("DHCP", "CLOSED", "Network auto-config - Router only"),
    68: ("DHCP-CLIENT", "CLOSED", "DHCP client - Handled by OS"),
    69: ("TFTP", "CLOSED", "Trivial FTP - Rarely used"),
    123: ("NTP", "CLOSED", "Network Time - Sync handled by OS"),
    137: ("NetBIOS-NS", "MAYBE OPEN", "Windows network naming"),
    138: ("NetBIOS-DGM", "MAYBE OPEN", "Windows datagram service"),
    161: ("SNMP", "CLOSED", "Network monitoring - Enterprise"),
    389: ("LDAP", "CLOSED", "Directory services - Corporate"),
    1433: ("MSSQL", "CLOSED", "Microsoft SQL Server - Enterprise only"),
    1723: ("PPTP", "CLOSED", "Old VPN - Insecure, deprecated"),
    5432: ("PostgreSQL", "CLOSED", "Postgres DB - Developer only"),
    5901: ("VNC-1", "CLOSED", "VNC display 1 - Rare"),
    6000: ("X11", "CLOSED", "Linux GUI - Local only"),
    6379: ("Redis", "CLOSED", "In-memory database - Dev only"),
    8000: ("Dev HTTP", "CLOSED", "Development web server"),
    8443: ("HTTPS-ALT", "CLOSED", "Alt secure web - Rare"),
    27017: ("MongoDB", "CLOSED", "NoSQL database - Dev only"),
}

COMMON_PORTS_LIST = sorted(PORT_KNOWLEDGE.keys())

# ===================================================================
# MAIN APPLICATION CLASS
# ===================================================================
class PortScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🔍 Network Port Scanner Pro")
        self.root.geometry("750x650")
        self.root.resizable(False, False)
        
        # Scan control
        self.scan_thread = None
        self.stop_event = threading.Event()
        
        # Results storage
        self.results_buffer = []
        self.scan_start_time = None
        
        self._build_ui()
        
    def _build_ui(self):
        """Professional UI with organized sections"""
        
        # ===== CONFIGURATION FRAME =====
        config = ttk.LabelFrame(self.root, text=" 🎯 Target Configuration ", padding=15)
        config.pack(fill="x", padx=20, pady=10)
        
        # Host input
        ttk.Label(config, text="Host/IP:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(config, width=40, textvariable=self.host_var, font=("Segoe UI", 10)).grid(row=0, column=1, padx=10, pady=5, columnspan=2)
        
        # Port range
        ttk.Label(config, text="Port Range:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        range_frame = ttk.Frame(config)
        range_frame.grid(row=1, column=1, sticky="w", pady=5)
        
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="100")
        
        ttk.Entry(range_frame, width=8, textvariable=self.start_port_var, font=("Segoe UI", 10)).pack(side=tk.LEFT)
        ttk.Label(range_frame, text="  ──  ", font=("Segoe UI", 10)).pack(side=tk.LEFT)
        ttk.Entry(range_frame, width=8, textvariable=self.end_port_var, font=("Segoe UI", 10)).pack(side=tk.LEFT)
        
        # Quick action buttons
        action_frame = ttk.Frame(config)
        action_frame.grid(row=2, column=1, pady=10, sticky="w")
        
        ttk.Button(action_frame, text="📋 Common Ports", width=18, command=self._quick_common).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="🌍 All Ports", width=18, command=self._quick_full).pack(side=tk.LEFT, padx=5)
        
        # ===== CONTROL BUTTONS =====
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10)
        
        self.scan_btn = ttk.Button(control_frame, text="▶ START SCAN", width=20, command=self._start_scan)
        self.scan_btn.grid(row=0, column=0, padx=10)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹ STOP", width=20, command=self._stop_scan, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=10)
        
        self.save_btn = ttk.Button(control_frame, text="💾 SAVE RESULTS", width=20, command=self._save_report)
        self.save_btn.grid(row=0, column=2, padx=10)
        
        # ===== PROGRESS & STATUS =====
        progress_frame = ttk.Frame(self.root)
        progress_frame.pack(fill="x", padx=20, pady=5)
        
        self.progress_bar = ttk.Progressbar(progress_frame, length=500, mode='determinate')
        self.progress_bar.pack(fill="x")
        
        self.status_var = tk.StringVar(value="⏳ Ready to scan...")
        ttk.Label(progress_frame, textvariable=self.status_var, font=("Segoe UI", 9, "italic")).pack()
        
        self.time_var = tk.StringVar(value="")
        ttk.Label(progress_frame, textvariable=self.time_var, font=("Segoe UI", 9)).pack()
        
        # ===== RESULTS DISPLAY =====
        result_frame = ttk.LabelFrame(self.root, text=" 📊 Live Scan Results ", padding=15)
        result_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, width=80, height=18, font=("Consolas", 9), bg="#fafafa")
        self.result_text.pack(fill="both", expand=True)
        
        # Setup text colors
        self.result_text.tag_configure("open", foreground="#2E7D32", font=("Consolas", 9, "bold"))
        self.result_text.tag_configure("closed", foreground="#C62828")
        self.result_text.tag_configure("error", foreground="#EF6C00", font=("Consolas", 9, "italic"))
        self.result_text.tag_configure("info", foreground="#1565C0", font=("Consolas", 9, "bold"))
        self.result_text.tag_configure("service", foreground="#616161")
        
    def _quick_common(self):
        """Pre-fill with common ports"""
        self.start_port_var.set("20")
        self.end_port_var.set("8080")
        self._add_status("✓ Quick select: Most common ports (20-8080)")
        
    def _quick_full(self):
        """Pre-fill with full port range"""
        self.start_port_var.set("1")
        self.end_port_var.set(str(MAX_PORT))
        self._add_status("⚠ Full range: All 65,535 ports (will be SLOW)")
        
    def _start_scan(self):
        """Validate and launch scan"""
        if self.scan_thread and self.scan_thread.is_alive():
            self._add_status("❌ Scan already running!", "error")
            return
        
        self.stop_event.clear()
        
        host = self.host_var.get().strip()
        try:
            start = int(self.start_port_var.get())
            end = int(self.end_port_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Ports must be NUMBERS!")
            return
        
        if not host:
            messagebox.showerror("Missing Host", "Enter IP (127.0.0.1) or domain")
            return
        if not (1 <= start <= MAX_PORT and 1 <= end <= MAX_PORT):
            messagebox.showerror("Invalid Range", f"Ports must be 1-{MAX_PORT}")
            return
        if start > end:
            messagebox.showerror("Logic Error", "Start port must be <= end port")
            return
        
        # Reset UI
        self.result_text.delete('1.0', tk.END)
        self.results_buffer = []
        self.scan_start_time = time.time()
        
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        
        # Start scan thread
        self.scan_thread = threading.Thread(target=self._scan_target, args=(host, start, end), daemon=True)
        self.scan_thread.start()
        self._add_status(f"🔍 Scanning {host}...")
        
    def _stop_scan(self):
        """Stop scan gracefully"""
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()
            self._add_status("⏹ Stopping scan...", "error")
        
    def _scan_target(self, host: str, start_port: int, end_port: int):
        """Main scanning logic"""
        try:
            ip = socket.gethostbyname(host)
            self._add_result(f"✓ Resolved {host} → {ip}\n", "info")
        except socket.gaierror:
            self._add_result(f"✗ Failed to resolve {host}\n", "error")
            self._end_scan()
            return
        
        total = end_port - start_port + 1
        scanned = 0
        open_count = 0
        
        for port in range(start_port, end_port + 1):
            if self.stop_event.is_set():
                self._add_result("\n⏹ Scan interrupted\n", "error")
                break
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(DEFAULT_TIMEOUT)
                    result = s.connect_ex((ip, port))
                    
                    if result == 0:
                        # PORT IS OPEN!
                        service_info = PORT_KNOWLEDGE.get(port, ("Unknown", "?", "No description"))
                        self._add_result(
                            f"🟢 PORT {port:5d}: OPEN    → {service_info[0]} ({service_info[2]})\n", 
                            "open"
                        )
                        open_count += 1
                    else:
                        # Port is closed (show every 10th to avoid clutter)
                        if port % 10 == 0:
                            self._add_result(f"🔴 PORT {port:5d}: Closed\n", "closed")
                            
            except Exception as e:
                self._add_result(f"⚠ PORT {port:5d}: Error ({e})\n", "error")
            
            # Update progress
            scanned += 1
            self._update_progress_bar(scanned, total)
            
            # Small delay to prevent CPU overload
            time.sleep(SCAN_DELAY)
        
        # Final summary
        elapsed = time.time() - self.scan_start_time
        self._add_result(
            f"\n📊 SUMMARY: {scanned} ports scanned in {elapsed:.1f}s. {open_count} open.\n", 
            "info"
        )
        self._end_scan()
        
    def _update_progress_bar(self, current: int, total: int):
        """Update progress"""
        self.progress_bar['value'] = current
        percent = (current / total) * 100
        elapsed = time.time() - self.scan_start_time
        self.time_var.set(f"Progress: {percent:.1f}% | Time: {elapsed:.1f}s")
        
    def _end_scan(self):
        """Restore UI state"""
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("✓ Scan complete. Save results if needed.")
        
    def _add_result(self, msg: str, tag: str):
        """Thread-safe result addition"""
        self.result_text.after(0, self._insert_text, msg, tag)
        self.results_buffer.append(msg)
        
    def _insert_text(self, msg: str, tag: str):
        """Insert colored text"""
        self.result_text.insert(tk.END, msg, tag)
        self.result_text.see(tk.END)
        
    def _add_status(self, msg: str, level: str = "info"):
        """Update status bar"""
        if level == "error":
            msg = f"❌ {msg}"
        self.result_text.after(0, self.status_var.set, msg)
        
    def _save_report(self):
        """Save scan results"""
        if not self.results_buffer:
            messagebox.showwarning("No Data", "Run a scan first before saving!")
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        filepath = os.path.join(desktop, f"PORT_SCAN_REPORT_{timestamp}.txt")
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("╔══════════════════════════════════════════════════════════════╗\n")
                f.write("║          NETWORK PORT SCAN REPORT - DETAILED                 ║\n")
                f.write("╚══════════════════════════════════════════════════════════════╝\n\n")
                f.write(f"Target Host: {self.host_var.get()}\n")
                f.write(f"Scan Range: {self.start_port_var.get()}-{self.end_port_var.get()}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-"*60 + "\n\n")
                f.writelines(self.results_buffer)
            
            self._add_status(f"✓ Report saved: {filepath}")
            messagebox.showinfo("Success", f"Report saved to Desktop:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Save Failed", str(e))

# ===================================================================
# LAUNCH APPLICATION
# ===================================================================
if __name__ == "__main__":
    root = tk.Tk()
    
    # Modern styling
    style = ttk.Style()
    try:
        style.theme_use('clam')
    except:
        pass
    
    app = PortScannerApp(root)
    root.mainloop()
