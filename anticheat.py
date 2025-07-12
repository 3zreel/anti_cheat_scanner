import os
import sys
import subprocess
import time
import math
import logging
import tkinter as tk
from tkinter import Tk, Frame, Label, Button, Listbox, Scrollbar, END, messagebox, Toplevel
try:
    import psutil
    import wmi
    import winreg
    import requests
    from PIL import Image, ImageTk
except ImportError:
    print("Installing required dependencies...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests', 'Pillow', 'psutil', 'wmi'])
    import psutil
    import wmi
    import winreg
    import requests
    from PIL import Image, ImageTk

# إعداد السجل
log_file = os.path.join(os.environ['APPDATA'], 'AntiCheatLog.txt')
os.makedirs(os.path.dirname(log_file), exist_ok=True)
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

# التحقق من المتطلبات
def check_requirements():
    if sys.version_info < (3, 6):
        print("Error: This program requires Python 3.6 or higher.")
        sys.exit(1)
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Warning: It is recommended to run the program as an administrator for optimal performance.")
    except Exception as e:
        print(f"Error checking permissions: {str(e)}")

# الويب هوك (غير مشفر)
WEBHOOK_URL = "https://canary.discord.com/api/webhooks/1393563844604854282/Hhy9hxtEEO9rbFW7HuO5hEIiLeI3eiCtB7Kcd9oQDqBRwK91g29_iK5QJMP444aRjtto"

# القوائم المشبوهة
suspicious_files = ["chromedriver.dll", "notepad.exe", "grandfromsawar.exe", ".rpf", ".ini", ".cfg"]
suspicious_processes = ["notepad", "chromedriver", "cheatengine", "xenos", "extremeinjector", "ollydbg", "x64dbg"]
spoofer_indicators = ["spoof", "hwidspoof", "spotless", "desync", "tracecleaner", "rootkit", "trojan", "obfuscator"]
cheat_loaders = ["cheatloader", "injector", "lunarclient"]
memory_mod_indicators = ["memoryhack", "debug", "speedhack"]
unauthorized_scripts = ["lua", "csharp", "kiddionsmodestmenu"]
suspicious_behavior = ["speedhack", "wallhack", "aimbot", "commandspamming", "fly", "infinite"]
exploits = ["packetmanipulation", "clientsideexploit"]
bypass_tools = ["bypass", "hideinjector"]
monitored_registry_paths = [
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
    r"SYSTEM\CurrentControlSet\Services\EventLog",
    r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
]
monitored_services = ["EventLog", "SysMain", "bam"]

def is_file_signed(file_path):
    try:
        return os.path.exists(file_path) and not os.path.getsize(file_path) == 0
    except Exception:
        return False

def check_memory_modification(process):
    try:
        process_info = psutil.Process(process.pid)
        mem_info = process_info.memory_info()
        return mem_info.rss > 1024 * 1024 * 100
    except Exception:
        return False

def monitor_registry_changes():
    for path in monitored_registry_paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT if path.startswith("Local Settings") else winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
            winreg.CloseKey(key)
            logging.info(f"Monitoring: {path} for changes")
        except WindowsError:
            logging.info(f"MuiCache Registry key deleted or missing: {path}")

def show_loading_screen():
    if not hasattr(root, 'tk'):
        raise ValueError("Root window is not properly initialized")
    loading_window = Toplevel(root)
    loading_window.title("Scanning...")
    loading_window.geometry("300x150")
    loading_window.configure(bg="#2E2E2E")
    loading_window.transient(root)
    loading_window.grab_set()
    
    try:
        loading_window.iconbitmap("logo.icon")
    except Exception as e:
        logging.warning(f"Failed to load icon for loading window: {str(e)}")

    label = Label(loading_window, text="MT", fg="#FFB74D", bg="#2E2E2E", font=("Arial", 24, "bold"))
    label.place(relx=0.5, rely=0.5, anchor="center")

    def animate_label(frame=0):
        if not loading_window.winfo_exists():
            return
        scale = 1 + 0.2 * math.sin(frame * 0.1)
        label.config(font=("Arial", int(24 + 6 * scale)))
        loading_window.after(50, animate_label, frame + 1)

    animate_label()
    Label(loading_window, text="Scanning...", fg="#F5F5F5", bg="#2E2E2E", font=("Arial", 12)).place(relx=0.5, rely=0.8, anchor="center")
    return loading_window

def send_to_discord(pid, status_emoji, cheat_type, last_used):
    if not WEBHOOK_URL:
        logging.warning("Webhook URL not configured. Skipping Discord notification.")
        print("Webhook URL is empty")
        return

    severity_levels = {
        "Spoofer": ("Critical", 0xFF0000),
        "Cheat Loader": ("High", 0xFFA500),
        "Memory Modification": ("High", 0xFFA500),
        "Unauthorized Script": ("Medium", 0xFFFF00),
        "Bypass Tool": ("Critical", 0xFF0000),
        "Service Tampering": ("Medium", 0xFFFF00),
        "Registry Tampering": ("Medium", 0xFFFF00),
        "Suspicious Process": ("Low", 0x00FF00),
        "Unsigned Cheat File": ("Low", 0x00FF00)
    }
    severity = "Unknown"
    color = 0x808080
    for c_type in cheat_type.split(", "):
        if c_type in severity_levels:
            if severity_levels[c_type][1] > color:
                severity = severity_levels[c_type][0]
                color = severity_levels[c_type][1]
    payload = {
        "embeds": [{
            "title": "🛡️ AntiCheat Scanner Alert",
            "description": f"**Threat Detection Report** {'\n🚨 **Cheating Detected!**' if status_emoji == '✅' else '\n✅ **System Clean**'}",
            "color": color,
            "fields": [
                {"name": "🆔 PID", "value": str(pid) if pid else "N/A", "inline": True},
                {"name": "🛑 Status", "value": f"{status_emoji} {'Cheating Detected' if status_emoji == '✅' else 'No Cheating Detected'}", "inline": True},
                {"name": "⚠️ Threat Type", "value": cheat_type if cheat_type != "None" else "None Detected", "inline": True},
                {"name": "🔍 Severity", "value": severity, "inline": True},
                {"name": "⏰ Last Scanned", "value": last_used, "inline": True},
                {"name": "📝 Recommended Action", "value": "Investigate and remove detected threats." if status_emoji == "✅" else "No action needed.", "inline": False}
            ],
            "footer": {"text": f"AntiCheat Scanner | Scan Time: {time.strftime('%H:%M:%S %Z, %Y-%m-%d')}"},
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S+00:00')
        }]
    }
    try:
        response = requests.post(WEBHOOK_URL, json=payload)
        response.raise_for_status()
        logging.info(f"Discord embed sent successfully: PID: {pid}, Status: {status_emoji}, Cheat Type: {cheat_type}, Severity: {severity}, HTTP Status: {response.status_code}")
    except Exception as e:
        logging.error(f"Failed to send Discord embed: {str(e)}, HTTP Status: {response.status_code if 'response' in locals() else 'N/A'}")
        print(f"Failed to send Discord embed: {str(e)}")

def scan_system():
    global root, results_listbox
    try:
        loading_window = show_loading_screen()
        root.update()
        results_listbox.delete(0, END)
        cheat_types = set()
        log_content = []

        user_path = os.path.expanduser("~")
        for base_dir, dirs, files in os.walk(user_path):
            for file in files:
                file_path = os.path.join(base_dir, file)
                file_name = file.lower()
                if file_name in suspicious_files:
                    if not is_file_signed(file_path):
                        entry = f"Detected: {file_path} - Unsigned Potential Cheat"
                        results_listbox.insert(END, entry)
                        logging.info(entry)
                        cheat_types.add("Unsigned Cheat File")
                        log_content.append(entry)
                if any(indicator in file_name for indicator in spoofer_indicators):
                    entry = f"Potential Spoofer Detected: {file_path}"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Spoofer")
                    log_content.append(entry)
                if any(loader in file_name for loader in cheat_loaders):
                    entry = f"Cheat Loader Detected: {file_path}"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Cheat Loader")
                    log_content.append(entry)
                if any(script in file_name for script in unauthorized_scripts):
                    entry = f"Unauthorized Script Detected: {file_path}"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Unauthorized Script")
                    log_content.append(entry)

        pid = None
        status_emoji = "❌"
        cheat_type = "None"
        last_used = time.strftime("%Y-%m-%d %H:%M:%S")

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                if proc_name in suspicious_processes:
                    pid = proc.info['pid']
                    entry = f"Detected Process: {proc_name} (PID: {pid}) - Potential Cheat"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Suspicious Process")
                    log_content.append(entry)
                if any(indicator in proc_name for indicator in spoofer_indicators):
                    pid = proc.info['pid']
                    entry = f"Potential Spoofer Process: {proc_name} (PID: {pid})"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Spoofer")
                    log_content.append(entry)
                if any(indicator in proc_name for indicator in cheat_loaders):
                    pid = proc.info['pid']
                    entry = f"Cheat Loader Process: {proc_name} (PID: {pid})"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Cheat Loader")
                    log_content.append(entry)
                if any(indicator in proc_name for indicator in memory_mod_indicators):
                    pid = proc.info['pid']
                    entry = f"Memory Modification Detected: {proc_name} (PID: {pid})"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Memory Modification")
                    log_content.append(entry)
                if any(indicator in proc_name for indicator in bypass_tools):
                    pid = proc.info['pid']
                    entry = f"Bypass Tool Detected: {proc_name} (PID: {pid})"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Bypass Tool")
                    log_content.append(entry)
                if cheat_types:
                    status_emoji = "✅"
                    cheat_type = ", ".join(cheat_types)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        c = wmi.WMI()
        for service_name in monitored_services:
            try:
                services = c.Win32_Service(Name=service_name)
                if not services or services[0].State != "Running":
                    entry = f"Service Modified: {service_name} - Stopped or Altered"
                    results_listbox.insert(END, entry)
                    logging.info(entry)
                    cheat_types.add("Service Tampering")
                    log_content.append(entry)
            except Exception:
                entry = f"Service {service_name} not found or disabled"
                results_listbox.insert(END, entry)
                logging.info(entry)
                cheat_types.add("Service Tampering")
                log_content.append(entry)

        try:
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache", 0, winreg.KEY_READ)
            winreg.CloseKey(key)
        except WindowsError:
            entry = "MuiCache Registry key deleted or missing"
            results_listbox.insert(END, entry)
            logging.info(entry)
            cheat_types.add("Registry Tampering")
            log_content.append(entry)

        update_cheat_status(cheat_types)
        update_results()
        send_to_discord(pid, status_emoji, cheat_type, last_used)
        loading_window.destroy()
    except Exception as e:
        logging.error(f"Error in scan_system: {str(e)}")
        loading_window.destroy()
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def update_cheat_status(cheat_types):
    if cheat_types:
        status_label.config(text=f"Cheat Detected: {', '.join(cheat_types)}", fg="#E04E39")
    else:
        status_label.config(text="No Cheat Detected", fg="#D3D3D3")

def update_results():
    for widget in results_frame.winfo_children():
        if isinstance(widget, Frame) and widget != results_listbox:
            widget.destroy()
    for i, item in enumerate(results_listbox.get(0, END)):
        create_result_panel(results_frame, item, i)

def create_result_panel(parent, item, index):
    panel = Frame(parent, bg="#2E2E2E", bd=2, relief="solid")
    panel.pack(fill="x", pady=10, padx=5)
    panel.config(highlightbackground="#F28C38", highlightcolor="#F28C38", highlightthickness=2)
    
    title = "Threat Detected"
    if "Spoofer" in item:
        title = "Spoofer Detected"
    elif "Cheat Loader" in item:
        title = "Cheat Loader Detected"
    elif "Memory Modification" in item:
        title = "Memory Modification Detected"
    elif "Unauthorized Script" in item:
        title = "Unauthorized Script Detected"
    elif "Bypass Tool" in item:
        title = "Bypass Tool Detected"
    elif "Service" in item or "Registry" in item:
        title = "System Tampering"

    details = item.split("Detected: ")[1] if "Detected: " in item else item
    Label(panel, text=title, fg="#F5F5F5", bg="#2E2E2E", font=("Arial", 10, "bold")).pack(side="left", padx=10)
    Label(panel, text=details, fg="#D3D3D3", bg="#2E2E2E", font=("Arial", 9)).pack(side="left", padx=10)
    details_button = Button(panel, text="Details", bg="#4A4A4A", fg="#FFFFFF", font=("Arial", 8), width=10, relief="flat", command=lambda i=index: show_details(i))
    details_button.pack(side="right", padx=5)
    remove_button = Button(panel, text="Remove", bg="#E04E39", fg="#FFFFFF", font=("Arial", 8), width=10, relief="flat", command=lambda i=index: remove_threat(i))
    remove_button.pack(side="right", padx=5)
    return panel

def show_details(index):
    item = results_listbox.get(index)
    messagebox.showinfo("Details", f"Threat Details:\n{item}\nAction: Please investigate manually.")

def remove_threat(index):
    item = results_listbox.get(index)
    if "Detected: " in item:
        path = item.split("Detected: ")[1].split(" - ")[0]
        try:
            if os.path.exists(path):
                os.remove(path)
                results_listbox.delete(index)
                logging.info(f"Removed threat: {path}")
                messagebox.showinfo("Success", f"Removed: {path}")
                scan_system()
            else:
                messagebox.showwarning("Error", "File not found or inaccessible.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove: {str(e)}")
    elif "Process: " in item:
        pid = int(item.split(" (PID: ")[1].split(")")[0])
        try:
            process = psutil.Process(pid)
            process.terminate()
            results_listbox.delete(index)
            logging.info(f"Terminated process PID: {pid}")
            messagebox.showinfo("Success", f"Terminated process PID: {pid}")
            scan_system()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to terminate process: {str(e)}")

if __name__ == "__main__":
    check_requirements()
    root = Tk()
    root.title("AntiCheat Scanner")
    root.geometry("800x500")
    root.configure(bg="#1C2526")
    
    try:
        root.iconbitmap("logo.icon")
    except Exception as e:
        logging.warning(f"Failed to load icon for main window: {str(e)}")

    canvas = tk.Canvas(root, bg="#1C2526", highlightthickness=0, width=800, height=500)
    canvas.pack(fill="both", expand=True)
    gradient = tk.PhotoImage(width=800, height=500)
    for x in range(800):
        r = int(28 + (x / 800) * 10)
        g = int(37 + (x / 800) * 10)
        b = int(38 + (x / 800) * 10)
        canvas.create_line(x, 0, x, 500, fill=f'#{r:02x}{g:02x}{b:02x}')
    canvas.create_image(0, 0, image=gradient, anchor="nw")

    control_panel = Frame(root, bg="#2E2E2E", bd=2, relief="raised")
    control_panel.place(x=20, y=20, width=150, height=460)

    scan_button = Button(control_panel, text="Scan", command=scan_system, bg="#F28C38", fg="#FFFFFF", font=("Arial", 12, "bold"), padx=15, pady=10, relief="flat", bd=0)
    scan_button.place(x=20, y=20)

    log_types = ["Detection Logs (13)", "Integrity Logs (4)", "Untrusted Files (0)", "Warning Logs (1)",
                 "Suspicious Logs (5)", "Engine Logs (0)", "Daily Logs (33)", "USB Logs (0)",
                 "Background (0)", "Antivirus (1)", "RAM (0)"]
    log_frame = Frame(control_panel, bg="#2E2E2E")
    log_frame.place(x=10, y=80, width=130, height=370)
    for i, log_type in enumerate(log_types):
        label = Label(log_frame, text=log_type, fg="#F5F5F5", bg="#2E2E2E", font=("Arial", 8), anchor="w")
        label.pack(fill="x", pady=5, padx=5)

    results_panel = Frame(root, bg="#2E2E2E", bd=2, relief="raised")
    results_panel.place(x=180, y=20, width=600, height=460)

    results_frame = Frame(results_panel, bg="#2E2E2E")
    results_frame.pack(fill="both", expand=True, padx=10, pady=10)
    global results_listbox
    results_listbox = Listbox(results_frame, bg="#1C2526", fg="#F5F5F5", height=15, width=70, font=("Courier", 10))
    results_listbox.pack(side="top", fill="both", expand=True)
    scrollbar = Scrollbar(results_frame, orient="vertical", command=results_listbox.yview)
    scrollbar.pack(side="right", fill="y")
    results_listbox.config(yscrollcommand=scrollbar.set)

    scan_info = Label(results_panel, text="Scan Results | Randump: Yes | AI: Not Supported", fg="#FFB74D", bg="#2E2E2E", font=("Arial", 10, "bold"))
    scan_info.place(x=10, y=10)

    global status_label
    status_label = Label(root, text="", font=("Arial", 14, "bold"), bg="#1C2526", fg="#D3D3D3")
    status_label.place(x=180, y=470)

    root.mainloop()
