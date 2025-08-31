import customtkinter as ctk
import tkinter as tk
from PIL import Image
import os
from pathlib import Path
import socket
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Appearance
        # Neon palette
        self.NEON_GREEN = "#56f500"   # matches your frame/labels
        self.NEON_RED   = "#ff004d"
        self.DARK_BG    = "#0D1117"   # app bg

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Nmap lite")
        self.geometry("800x600")
        self.configure(fg_color="#0D1117")

        # layout
        self.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)

        # assets dir
        assets_dir = Path("assets")
        assets_dir.mkdir(exist_ok=True)

        # image refs
        self._image_references = []

        # scanning state
        self.scan_queue = queue.Queue()
        self.scanning = False
        self.stop_event = threading.Event()

        # widgets
        self.create_widgets()

        # poll queue periodically
        self.after(100, lambda: self._process_queue())


    def create_widgets(self):
        """Create and place all widgets (kept original placements)"""
        self.label_1756596408355 = ctk.CTkLabel(self, text="Enter IP address or domain", width=156, height=42, corner_radius=5, fg_color="#56f500", text_color="#000000", font=("Arial", 12, "bold"))
        self.label_1756596408355.place(x=63, y=61)

        self.label_1756597060957 = ctk.CTkLabel(self, text="Enter start port", width=156, height=30, corner_radius=5, fg_color="#56f500", text_color="#000000", font=("Arial", 12, "bold"))
        self.label_1756597060957.place(x=63, y=117)

        self.label_1756597100382 = ctk.CTkLabel(self, text="Enter end port", width=156, height=30, corner_radius=5, fg_color="#56f500", text_color="#000000", font=("Arial", 12, "bold"))
        self.label_1756597100382.place(x=63, y=159)

        self.entry_1756597129327 = ctk.CTkEntry(self, width=200, height=40, corner_radius=8, fg_color="#ffffff", text_color="#000000", border_width=1, border_color="#e2e8f0", placeholder_text="e.g. 192.168.1.1 or example.com", font=("Arial", 12, "normal"))
        self.entry_1756597129327.place(x=243, y=63)

        self.entry_1756597136071 = ctk.CTkEntry(self, width=200, height=40, corner_radius=8, fg_color="#ffffff", text_color="#000000", border_width=1, border_color="#e2e8f0", placeholder_text="Start port (e.g. 1)", font=("Arial", 12, "normal"))
        self.entry_1756597136071.place(x=243, y=111)

        self.entry_1756597140502 = ctk.CTkEntry(self, width=200, height=40, corner_radius=8, fg_color="#ffffff", text_color="#000000", border_width=1, border_color="#e2e8f0", placeholder_text="End port (e.g. 1024)", font=("Arial", 12, "normal"))
        self.entry_1756597140502.place(x=243, y=155)

# START button -> start_scan
        self.button_1756597201159 = ctk.CTkButton(
    self,
    text="START",
    width=120,
    height=40,
    corner_radius=8,
    fg_color=self.DARK_BG,          # dark base
    hover_color=self.NEON_GREEN,    # neon on hover ✅
    text_color="#FFFFFF",           # readable on both base & neon
    border_width=1,
    border_color=self.NEON_GREEN,   # subtle neon border
    font=("Arial", 12, "bold"),
    command=self.start_scan
)
        self.button_1756597201159.place(x=228, y=215)
        self.button_1756597201159.configure(cursor="hand2")

# STOP button -> stop_scan
        self.button_1756599451853 = ctk.CTkButton(
    self,
    text="STOP",
    width=120,
    height=40,
    corner_radius=8,
    fg_color=self.DARK_BG,          # dark base
    hover_color=self.NEON_RED,      # neon on hover ✅
    text_color="#FFFFFF",
    border_width=1,
    border_color=self.NEON_RED,
    font=("Arial", 12, "bold"),
    command=self.stop_scan,
    state="disabled"
)
        self.button_1756599451853.place(x=363, y=215)
        self.button_1756599451853.configure(cursor="hand2")


        self.frame_1756597517943 = ctk.CTkFrame(self, width=600, height=258, corner_radius=8, fg_color="#161B22", border_width=1, border_color="#56f500")
        self.frame_1756597517943.place(x=66, y=273)

        self.output_text = tk.Text(self.frame_1756597517943, bg="#161B22", fg="#00ff7f", wrap="word", font=("Consolas", 11), bd=0, highlightthickness=0)
        self.output_text.place(relx=.01, rely=.01, relwidth=.94, relheight=.84)

        self.scrollbar = tk.Scrollbar(self.frame_1756597517943, command=self.output_text.yview, bg="#161B22", troughcolor="#161B22", bd=0)
        self.output_text.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.place(relx=.96, rely=.01, relheight=.84, anchor="ne")

        try:
            self.progressbar_1756599554230 = ctk.CTkProgressBar(self.frame_1756597517943, width=560)
            self.progressbar_1756599554230.set(0.0)
            self.progressbar_1756599554230.place(relx=.02, rely=.88, relwidth=.96)
            self.progressbar = self.progressbar_1756599554230
        except Exception:
            from tkinter import ttk
            self.progressbar = ttk.Progressbar(self.frame_1756597517943, orient="horizontal", length=560, mode="determinate")
            self.progressbar.place(relx=.02, rely=.88, relwidth=.96)

        self.output_text.tag_configure("neon", foreground="#00ff7f")
        self.output_text.tag_configure("info", foreground="#58A6FF")
        self.output_text.tag_configure("error", foreground="#FF4D4D")
        self.output_text.tag_configure("bold", font=("Consolas", 11, "bold"))

    def _append_line(self, text, tag="neon"):
        """Insert a full line (fast)."""
        try:
            self.output_text.insert(tk.END, text + "\n", tag)
            self.output_text.see(tk.END)
        except Exception:
            self.output_text.insert(tk.END, text + "\n")
            self.output_text.see(tk.END)

    def _type_text(self, text, tag="neon", char_delay=10):
        """Type text into the output_text widget char-by-char (non-blocking using after)."""
        i = 0
        def step():
            nonlocal i
            if i < len(text):
                try:
                    self.output_text.insert(tk.END, text[i], tag)
                except Exception:
                    self.output_text.insert(tk.END, text[i])
                self.output_text.see(tk.END)
                i += 1
                self.after(char_delay, step)
            else:
                if not text.endswith("\n"):
                    self.output_text.insert(tk.END, "\n", tag)
                    self.output_text.see(tk.END)
        step()

    def _set_progress(self, fraction):
        """Set progress 0..1 (compatible with CTkProgressBar or ttk)."""
        try:
            self.progressbar.set(fraction)
        except Exception:
            try:
                self.progressbar['value'] = fraction * 100
                self.frame_1756597517943.update_idletasks()
            except Exception:
                pass

    def start_scan(self):
        if self.scanning:
            return

        target = self.entry_1756597129327.get().strip()
        start_str = self.entry_1756597136071.get().strip()
        end_str = self.entry_1756597140502.get().strip()

        if not target:
            tk.messagebox.showerror("Input Error", "Please enter a target IP or domain.")
            return

        try:
            start_port = int(start_str)
            end_port = int(end_str)
        except Exception:
            tk.messagebox.showerror("Input Error", "Start and end ports must be integers.")
            return

        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            tk.messagebox.showerror("Input Error", "Ports must be in range 1-65535.")
            return

        if start_port > end_port:
            tk.messagebox.showerror("Input Error", "Start port must be <= end port.")
            return

        self.button_1756597201159.configure(state="disabled", text="SCANNING...")
        self.button_1756599451853.configure(state="normal")
        self.scanning = True
        self.stop_event.clear()
        self.output_text.delete("1.0", tk.END)
        self._append_line(f"[+] Starting scan: {target} ports {start_port}-{end_port}", tag="info")
        self._set_progress(0.0)

        try:
            resolved_ip = socket.gethostbyname(target)
            self._append_line(f"[i] Resolved {target} -> {resolved_ip}", tag="info")
            target_ip = resolved_ip
        except Exception as e:
            self._append_line(f"[!] Could not resolve '{target}' - using raw input (error: {e})", tag="error")
            target_ip = target

        thread = threading.Thread(target=self._scan_thread, args=(target_ip, start_port, end_port), daemon=True)
        thread.start()

    def stop_scan(self):
        if not self.scanning:
            return
        self.stop_event.set()
        self._append_line("[!] Stop requested. Stopping...", tag="info")
        self.button_1756599451853.configure(state="disabled")

    def _scan_port_once(self, ip, port, timeout=0.5):
        """Return True if port is open; respects stop_event by early check."""
        if self.stop_event.is_set():
            return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                return result == 0
        except Exception:
            return False

    def _scan_thread(self, ip, start_port, end_port):
        """Run in background: submit port checks to a ThreadPoolExecutor, post results to queue."""
        try:
            total_ports = (end_port - start_port) + 1
            if total_ports <= 0:
                self.scan_queue.put(("error", "Invalid port range"))
                self.scan_queue.put(("done", []))
                return

            max_workers = min(50, total_ports)  # Reduced for stability
            open_ports = []
            completed = 0

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {executor.submit(self._scan_port_once, ip, port): port for port in range(start_port, end_port + 1)}

                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    if self.stop_event.is_set():
                        for f in future_to_port:
                            if not f.done():
                                try:
                                    f.cancel()
                                except Exception:
                                    pass
                        break

                    try:
                        res = future.result()
                    except Exception as e:
                        self.scan_queue.put(("error", f"Port {port} scan error: {e}"))
                        res = False

                    completed += 1
                    frac = completed / total_ports
                    self.scan_queue.put(("progress", frac))

                    if res is True:
                        open_ports.append(port)
                        self.scan_queue.put(("open", port))

                if self.stop_event.is_set():
                    self.scan_queue.put(("done", sorted(open_ports)))
                else:
                    self.scan_queue.put(("done", sorted(open_ports)))
        except Exception as e:
            self.scan_queue.put(("error", f"Scanning failed: {e}\n{traceback.format_exc()}"))
            self.scan_queue.put(("done", []))

    def _process_queue(self):
        """Consume queue messages on the main thread and update UI."""
        try:
            while not self.scan_queue.empty():
                typ, payload = self.scan_queue.get_nowait()

                if typ == "progress":
                    frac = payload
                    self._set_progress(frac)

                elif typ == "open":
                    port = payload
                    self._append_line(f"[OPEN] Port {port}", tag="neon")

                elif typ == "error":
                    self._append_line(f"[ERROR] {payload}", tag="error")

                elif typ == "done":
                    open_list = payload or []
                    self._set_progress(1.0)
                    self._append_line("\n--- Scan Complete ---", tag="info")
                    if open_list:
                        self._type_text(f"[+] Open ports: {', '.join(map(str, open_list))}\n", tag="neon", char_delay=6)
                    else:
                        self._append_line("[-] No open ports found.", tag="neon")
                    self.button_1756597201159.configure(state="normal", text="START")
                    self.button_1756599451853.configure(state="disabled")
                    self.scanning = False

        except Exception:
            traceback.print_exc()
        finally:
            self.after(100, self._process_queue)

    def load_image(self, path, size):
        """Load an image, resize it and return as CTkImage."""
        try:
            path_str = str(path)
            if os.path.exists(path_str):
                img = Image.open(path_str)
                img = img.resize(size, Image.LANCZOS if hasattr(Image, 'LANCZOS') else Image.Resampling.LANCZOS)
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=size)
                self._image_references.append(ctk_img)
                return ctk_img
            else:
                placeholder_path = "assets/placeholder.png"
                if os.path.exists(placeholder_path):
                    img = Image.open(placeholder_path)
                    img = img.resize(size, Image.LANCZOS if hasattr(Image, 'LANCZOS') else Image.Resampling.LANCZOS)
                    ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=size)
                    self._image_references.append(ctk_img)
                    return ctk_img
                else:
                    img = Image.new('RGB', size, color='#3B82F6')
                    ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=size)
                    self._image_references.append(ctk_img)
                    return ctk_img
        except Exception as e:
            print(f"Error loading image '{path}': {e}")
            try:
                img = Image.new('RGB', size, color='#FF5555')
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=size)
                self._image_references.append(ctk_img)
                return ctk_img
            except Exception as e2:
                print(f"Failed to create error placeholder: {e2}")
                return None

if __name__ == "__main__":
    try:
        app = App()
        app.mainloop()
    except Exception as e:
        print(f"Error running application: {e}")
        traceback.print_exc()