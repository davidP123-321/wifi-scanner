import subprocess
import re
import socket
import threading
import csv
import os
from datetime import datetime
from ipaddress import ip_network, ip_address
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

class WiFiScanner:
    def __init__(self):
        self.wifi_networks = []
        self.devices = []
        self.is_scanning = False

    def run_command(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            if result.returncode == 0:
                return result.stdout
            return ""
        except Exception as e:
            return ""

    def scan_wifi_networks(self):
        output = self.run_command("netsh wlan show networks mode=Bssid")
        networks = []
        current = None

        if not output:
            return networks

        for raw_line in output.splitlines():
            line = raw_line.strip()

            if not line:
                continue

            # SSID
            match = re.match(r"^SSID\s+\d+\s*:\s*(.+)$", line, re.IGNORECASE)
            if match:
                if current and current.get("ssid"):
                    networks.append(current)
                current = {"ssid": match.group(1).strip()}
                continue

            if current is None:
                continue

            # Signal
            signal_match = re.match(r"^Signal\s*:\s*(\d+)%?$", line, re.IGNORECASE)
            if signal_match:
                current["signal"] = signal_match.group(1) + "%"
                continue

            # BSSID
            bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*(.+)$", line, re.IGNORECASE)
            if bssid_match:
                current["bssid"] = bssid_match.group(1).strip()
                continue

            # Radio Type
            radio_match = re.match(r"^Radio type\s*:\s*(.+)$", line, re.IGNORECASE)
            if radio_match:
                current["radio"] = radio_match.group(1).strip()
                continue

            # Channel
            channel_match = re.match(r"^Channel\s*:\s*(\d+)$", line, re.IGNORECASE)
            if channel_match:
                current["channel"] = channel_match.group(1)
                continue

            # Security
            security_match = re.match(r"^Authentication\s*:\s*(.+)$", line, re.IGNORECASE)
            if security_match:
                current["auth"] = security_match.group(1).strip()
                continue

            # Encryption
            encryption_match = re.match(r"^Encryption\s*:\s*(.+)$", line, re.IGNORECASE)
            if encryption_match:
                current["encryption"] = encryption_match.group(1).strip()
                continue

        if current and current.get("ssid"):
            networks.append(current)

        self.wifi_networks = networks
        return networks

    def get_local_ip(self):
        try:
            # Se connecte à un serveur externe pour trouver l'IP locale
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.1"

    def get_network_range(self):
        local_ip = self.get_local_ip()
        try:
            # Assume un réseau /24
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            return "192.168.1.0/24"

    def ping_device(self, ip):
        try:
            result = subprocess.run(
                f"ping -n 1 -w 500 {ip}",
                capture_output=True,
                text=True,
                shell=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False

    def scan_arp_table(self):
        output = self.run_command("arp -a")
        devices = []

        if not output:
            return devices

        for raw_line in output.splitlines():
            line = raw_line.strip()
            match = re.match(
                r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f\-]{17})",
                line
            )

            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":")
                devices.append({"ip": ip, "mac": mac, "source": "ARP"})

        return devices

    def scan_network_ping(self, callback=None):
        """Scanne le réseau via ping"""
        devices = []
        network_range = self.get_network_range()

        try:
            net = ip_network(network_range, strict=False)
            ips = list(net.hosts())

            total = len(ips)
            for idx, ip in enumerate(ips):
                if not self.is_scanning:
                    break

                ip_str = str(ip)
                if self.ping_device(ip_str):
                    # Cherche le MAC via ARP
                    arp_output = self.run_command(f"arp -a {ip_str}")
                    mac = "unknown"
                    match = re.search(r"([0-9A-Fa-f\-]{17})", arp_output)
                    if match:
                        mac = match.group(1).replace("-", ":")

                    devices.append({"ip": ip_str, "mac": mac, "source": "Ping", "online": True})

                if callback:
                    callback(f"Ping: {idx+1}/{total}", (idx + 1) / total)

        except Exception as e:
            pass

        return devices

    def scan_devices_combined(self, callback=None):
        """Combine ARP + Ping"""
        devices = []

        # 1. ARP d'abord (rapide)
        arp_devices = self.scan_arp_table()
        devices.extend(arp_devices)

        if callback:
            callback("Scan ARP terminé, lancement du ping...", 0.3)

        # 2. Ping sur le réseau
        ping_devices = self.scan_network_ping(callback)

        # Merge et déduplication
        seen = {}
        for d in devices + ping_devices:
            key = d["ip"]
            if key not in seen:
                seen[key] = d
            elif d.get("source") == "Ping":
                seen[key].update(d)

        self.devices = list(seen.values())
        return self.devices

    def export_csv(self, filename):
        """Exporte les résultats en CSV"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                # WiFi networks
                writer = csv.writer(csvfile)
                writer.writerow(["=== RESEAUX WI-FI ==="])
                writer.writerow(["SSID", "Signal", "Canal", "BSSID", "Radio Type", "Authentification", "Chiffrement"])

                for net in self.wifi_networks:
                    writer.writerow([
                        net.get("ssid", "N/A"),
                        net.get("signal", "N/A"),
                        net.get("channel", "N/A"),
                        net.get("bssid", "N/A"),
                        net.get("radio", "N/A"),
                        net.get("auth", "N/A"),
                        net.get("encryption", "N/A")
                    ])

                writer.writerow([])
                writer.writerow(["=== APPAREILS DU RESEAU LOCAL ==="])
                writer.writerow(["IP", "MAC", "En ligne", "Source"])

                for dev in self.devices:
                    writer.writerow([
                        dev.get("ip", "N/A"),
                        dev.get("mac", "N/A"),
                        "Oui" if dev.get("online") else "Non",
                        dev.get("source", "N/A")
                    ])

            return True
        except Exception as e:
            return False


class WiFiScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Scanner Pro - Windows")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        self.scanner = WiFiScanner()
        self.is_scanning = False

        # Style
        style = ttk.Style()
        style.theme_use('clam')

        # Main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Title
        title = ttk.Label(main_frame, text="WiFi Scanner Pro", font=("Arial", 16, "bold"))
        title.grid(row=0, column=0, columnspan=3, pady=10)

        # Buttons frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E))

        self.btn_scan = ttk.Button(btn_frame, text="Démarrer le scan", command=self.start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(btn_frame, text="Arrêter", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_export = ttk.Button(btn_frame, text="Exporter en CSV", command=self.export_csv)
        self.btn_export.pack(side=tk.LEFT, padx=5)

        self.btn_clear = ttk.Button(btn_frame, text="Effacer", command=self.clear_output)
        self.btn_clear.pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        self.status_label = ttk.Label(main_frame, text="Prêt", foreground="blue")
        self.status_label.grid(row=3, column=0, columnspan=3, pady=5)

        # Notebook (onglets)
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)

        # Onglet WiFi
        wifi_frame = ttk.Frame(notebook)
        notebook.add(wifi_frame, text="Réseaux Wi-Fi")

        self.wifi_text = ScrolledText(wifi_frame, height=20, width=100, state=tk.DISABLED)
        self.wifi_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Onglet Appareils
        devices_frame = ttk.Frame(notebook)
        notebook.add(devices_frame, text="Appareils")

        self.devices_text = ScrolledText(devices_frame, height=20, width=100, state=tk.DISABLED)
        self.devices_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Onglet Log
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Journal")

        self.log_text = ScrolledText(log_frame, height=20, width=100, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure grid weights for resizing
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)

    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.root.update()

    def update_progress(self, message, value):
        self.status_label.config(text=message)
        self.progress['value'] = value * 100
        self.root.update()

    def display_wifi(self):
        self.wifi_text.config(state=tk.NORMAL)
        self.wifi_text.delete(1.0, tk.END)

        if not self.scanner.wifi_networks:
            self.wifi_text.insert(tk.END, "Aucun réseau Wi-Fi détecté.\n")
        else:
            for i, net in enumerate(self.scanner.wifi_networks, 1):
                self.wifi_text.insert(tk.END, f"\n{'='*80}\n")
                self.wifi_text.insert(tk.END, f"Réseau {i}\n")
                self.wifi_text.insert(tk.END, f"{'='*80}\n")
                self.wifi_text.insert(tk.END, f"SSID           : {net.get('ssid', 'N/A')}\n")
                self.wifi_text.insert(tk.END, f"Signal         : {net.get('signal', 'N/A')}\n")
                self.wifi_text.insert(tk.END, f"Canal          : {net.get('channel', 'N/A')}\n")
                self.wifi_text.insert(tk.END, f"BSSID (MAC)    : {net.get('bssid', 'N/A')}\n")
                self.wifi_text.insert(tk.END, f"Type Radio     : {net.get('radio', 'N/A')}\n")
                self.wifi_text.insert(tk.END, f"Authentification : {net.get('auth', 'N/A')}\n")
                self.wifi_text.insert(tk.END, f"Chiffrement    : {net.get('encryption', 'N/A')}\n")

        self.wifi_text.config(state=tk.DISABLED)

    def display_devices(self):
        self.devices_text.config(state=tk.NORMAL)
        self.devices_text.delete(1.0, tk.END)

        if not self.scanner.devices:
            self.devices_text.insert(tk.END, "Aucun appareil détecté.\n")
        else:
            self.devices_text.insert(tk.END, f"{'IP':<15} {'MAC':<20} {'En ligne':<12} {'Source':<10}\n")
            self.devices_text.insert(tk.END, f"{'-'*15} {'-'*20} {'-'*12} {'-'*10}\n")

            for dev in sorted(self.scanner.devices, key=lambda x: x['ip']):
                ip = dev.get("ip", "N/A")
                mac = dev.get("mac", "unknown")
                online = "Oui ✓" if dev.get("online") else "Non"
                source = dev.get("source", "N/A")
                self.devices_text.insert(tk.END, f"{ip:<15} {mac:<20} {online:<12} {source:<10}\n")

        self.devices_text.config(state=tk.DISABLED)

    def start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Attention", "Un scan est déjà en cours.")
            return

        self.is_scanning = True
        self.scanner.is_scanning = True
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress['value'] = 0
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Démarrage du scan...\n")

        # Thread pour le scan
        thread = threading.Thread(target=self.run_scan)
        thread.daemon = True
        thread.start()

    def run_scan(self):
        try:
            self.update_progress("Scan WiFi...", 0.1)
            self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Scan des réseaux WiFi...")
            self.scanner.scan_wifi_networks()
            self.log(f"[{datetime.now().strftime('%H:%M:%S')}] {len(self.scanner.wifi_networks)} réseau(x) trouvé(s)")
            self.display_wifi()

            self.update_progress("Scan des appareils...", 0.3)
            self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Scan des appareils du réseau...")
            self.scanner.scan_devices_combined(self.update_progress)
            self.log(f"[{datetime.now().strftime('%H:%M:%S')}] {len(self.scanner.devices)} appareil(s) détecté(s)")
            self.display_devices()

            self.update_progress("Scan terminé ✓", 1.0)
            self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Scan terminé avec succès")

        except Exception as e:
            self.log(f"[ERREUR] {str(e)}")
            messagebox.showerror("Erreur", f"Une erreur s'est produite:\n{str(e)}")

        finally:
            self.is_scanning = False
            self.scanner.is_scanning = False
            self.btn_scan.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)

    def stop_scan(self):
        self.scanner.is_scanning = False
        self.is_scanning = False
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Scan arrêté par l'utilisateur")
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.update_progress("Arrêté", 0)

    def export_csv(self):
        if not self.scanner.wifi_networks and not self.scanner.devices:
            messagebox.showwarning("Attention", "Aucune donnée à exporter. Fais d'abord un scan.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )

        if filename:
            if self.scanner.export_csv(filename):
                self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Export réussi: {filename}")
                messagebox.showinfo("Succès", f"Export réussi:\n{filename}")
            else:
                self.log(f"[{datetime.now().strftime('%H:%M:%S')}] Erreur lors de l'export")
                messagebox.showerror("Erreur", "Erreur lors de l'export du fichier")

    def clear_output(self):
        self.wifi_text.config(state=tk.NORMAL)
        self.wifi_text.delete(1.0, tk.END)
        self.wifi_text.config(state=tk.DISABLED)

        self.devices_text.config(state=tk.NORMAL)
        self.devices_text.delete(1.0, tk.END)
        self.devices_text.config(state=tk.DISABLED)

        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

        self.progress['value'] = 0
        self.status_label.config(text="Prêt")


if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiScannerGUI(root)
    root.mainloop()
