"""
VayroScan – port scanner thingy
scans all ports 1-65535
"""

import customtkinter as ctk
import tkinter as tk
import socket
import threading
import math
from datetime import datetime
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor

# dark mode always
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# colors – eyeballed
BG = "#060a0f"
BG2 = "#0d1117"
BG3 = "#111820"
CYAN = "#00d4ff"
CYAN_DIM = "#007a94"
GREEN = "#00ff95"
RED = "#ff3c5a"
AMBER = "#ffb347"
GRAY = "#3a4450"
GRAY_LT = "#5a6470"
TEXT = "#cdd6e0"
ACCENT = "#1a2535"

# common services (not all 65535, just the usual suspects)
SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 443:"HTTPS", 445:"SMB", 3306:"MySQL", 3389:"RDP",
    5432:"PostgreSQL", 8080:"HTTP-Proxy", 8443:"HTTPS-alt",
}

# full port range
PORT_START = 1
PORT_END = 65535
TIMEOUT = 0.5   # seconds, fixed

# ------------------------------------------------------------
# animated glow button (because why not)
# ------------------------------------------------------------
class GlowButton(tk.Frame):
    GLOW_R, GLOW_G, GLOW_B = 0, 212, 255
    BG_R, BG_G, BG_B = 6, 10, 15

    def __init__(self, master, text, command=None, btn_width=178, btn_height=38, layers=10, **kwargs):
        pad = layers * 3
        super().__init__(master, bg=BG, bd=0, highlightthickness=0)

        cw = btn_width + pad*2
        ch = btn_height + pad*2
        self._pad = pad
        self._bw = btn_width
        self._bh = btn_height
        self._layers = layers
        self._phase = 0.0

        self._canvas = tk.Canvas(self, width=cw, height=ch, bg=BG, highlightthickness=0, bd=0)
        self._canvas.pack()

        self._btn = ctk.CTkButton(
            self._canvas, text=text, command=command,
            width=btn_width, height=btn_height,
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=ACCENT, hover_color="#1f3048",
            text_color=CYAN, border_width=1, border_color=CYAN_DIM,
            corner_radius=6,
        )
        self._canvas.create_window(cw//2, ch//2, window=self._btn)
        self._animate()

    def _lerp(self, a, b, t):
        return int(a + (b-a)*t)

    def _glow_color(self, proximity):
        r = self._lerp(self.BG_R, self.GLOW_R, proximity)
        g = self._lerp(self.BG_G, self.GLOW_G, proximity)
        b = self._lerp(self.BG_B, self.GLOW_B, proximity)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _animate(self):
        self._phase += 0.055
        intensity = (math.sin(self._phase) * 0.45 + 0.55)

        self._canvas.delete("glow")
        cx = (self._bw + self._pad*2)//2
        cy = (self._bh + self._pad*2)//2
        hw, hh = self._bw//2, self._bh//2

        for i in range(self._layers, 0, -1):
            spread = i*3
            prox = (1 - i/self._layers) * intensity
            color = self._glow_color(max(0.0, prox))
            x1 = cx - hw - spread
            y1 = cy - hh - spread
            x2 = cx + hw + spread
            y2 = cy + hh + spread
            self._canvas.create_rectangle(x1, y1, x2, y2, outline=color, width=1, tags="glow")
        self.after(45, self._animate)


# ------------------------------------------------------------
# stat card – shows a number
# ------------------------------------------------------------
class StatCard(ctk.CTkFrame):
    def __init__(self, master, label, value="0", value_color=CYAN, **kwargs):
        super().__init__(master, corner_radius=10, fg_color=BG3, border_width=1, border_color=GRAY, **kwargs)
        ctk.CTkLabel(self, text=label, font=ctk.CTkFont(family="Consolas", size=11), text_color=GRAY_LT).pack(pady=(10,0))
        self.val_label = ctk.CTkLabel(self, text=value, font=ctk.CTkFont(family="Consolas", size=22, weight="bold"), text_color=value_color)
        self.val_label.pack(pady=(0,10))

    def set(self, val):
        self.val_label.configure(text=str(val))


# ------------------------------------------------------------
# main app
# ------------------------------------------------------------
class VayroScan(ctk.CTk):
    THREAD_OPTS = [100, 200, 300, 500, 800]

    def __init__(self):
        super().__init__()
        self.title("VayroScan")
        self.geometry("860x700")
        self.minsize(720, 560)
        self.configure(fg_color=BG)

        self.scanning = False
        self.stop_event = threading.Event()
        self.result_queue = Queue()
        self.open_count = 0
        self.closed_count = 0
        self.total_ports = PORT_END - PORT_START + 1   # 65535
        self.start_time = None

        self._build_ui()
        self._poll_queue()

    # --------------------------------------------------------
    # build all ui components
    # --------------------------------------------------------
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # header
        hdr = tk.Frame(self, bg=BG, height=90)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        tk.Frame(hdr, bg=CYAN, width=4).place(x=28, y=16, height=58)
        tk.Label(hdr, text="VAYRO", font=("Consolas", 34, "bold"), fg=CYAN, bg=BG).place(x=42, y=10)
        tk.Label(hdr, text="SCAN", font=("Consolas", 34, "bold"), fg=TEXT, bg=BG).place(x=42+110, y=10)
        tk.Label(hdr, text="fast  ·  simple  ·  precise", font=("Consolas", 11), fg=GRAY_LT, bg=BG).place(x=44, y=58)

        self.status_label = tk.Label(hdr, text="● IDLE", font=("Consolas", 11, "bold"), fg=GRAY_LT, bg=BG)
        self.status_label.place(relx=1.0, x=-28, y=36, anchor="e")

        tk.Frame(self, bg=GRAY, height=1).grid(row=0, column=0, sticky="sew", padx=0)

        # config panel
        cfg = ctk.CTkFrame(self, corner_radius=0, fg_color=BG2, border_width=0)
        cfg.grid(row=1, column=0, sticky="ew", padx=0, pady=0)
        cfg.grid_columnconfigure(1, weight=1)

        row0 = ctk.CTkFrame(cfg, fg_color="transparent")
        row0.grid(row=0, column=0, padx=20, pady=(14,14), sticky="ew")
        row0.grid_columnconfigure(1, weight=1)

        # target
        tk.Label(row0, text="TARGET", bg=BG2, fg=GRAY_LT, font=("Consolas",10,"bold")).grid(row=0, column=0, sticky="w", padx=(0,8))
        self.target_entry = ctk.CTkEntry(row0, placeholder_text="hostname or IP", height=36,
                                          font=ctk.CTkFont(family="Consolas", size=13),
                                          fg_color=BG3, border_color=GRAY, text_color=TEXT)
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=(0,20))

        # threads
        tk.Label(row0, text="THREADS", bg=BG2, fg=GRAY_LT, font=("Consolas",10,"bold")).grid(row=0, column=2, sticky="w", padx=(0,8))
        self.threads_var = ctk.StringVar(value="300")
        ctk.CTkOptionMenu(row0, variable=self.threads_var, values=[str(n) for n in self.THREAD_OPTS],
                          width=80, height=36, fg_color=BG3, button_color=GRAY,
                          font=ctk.CTkFont(family="Consolas", size=12)).grid(row=0, column=3)

        # stats row
        stats = ctk.CTkFrame(self, corner_radius=0, fg_color=BG, border_width=0)
        stats.grid(row=2, column=0, padx=20, pady=(10,0), sticky="ew")
        for i in range(3):
            stats.grid_columnconfigure(i, weight=1)

        self.open_card = StatCard(stats, "OPEN PORTS", "0", GREEN)
        self.closed_card = StatCard(stats, "CLOSED PORTS", "0", GRAY_LT)
        self.total_card = StatCard(stats, "TOTAL PORTS", str(self.total_ports), CYAN)
        self.open_card.grid(row=0, column=0, padx=(0,6), sticky="ew")
        self.closed_card.grid(row=0, column=1, padx=6, sticky="ew")
        self.total_card.grid(row=0, column=2, padx=(6,0), sticky="ew")

        # output terminal
        term_wrap = ctk.CTkFrame(self, corner_radius=10, fg_color=BG2, border_width=1, border_color=GRAY)
        term_wrap.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
        term_wrap.grid_columnconfigure(0, weight=1)
        term_wrap.grid_rowconfigure(1, weight=1)

        tbar = tk.Frame(term_wrap, bg=BG3, height=30)
        tbar.grid(row=0, column=0, sticky="ew")
        tbar.grid_propagate(False)
        for col, color in enumerate([RED, AMBER, GREEN]):
            tk.Label(tbar, text="●", fg=color, bg=BG3, font=("Consolas",11)).place(x=12+col*18, y=7)
        tk.Label(tbar, text="scan output", fg=GRAY_LT, bg=BG3, font=("Consolas",11)).place(relx=0.5, y=7, anchor="n")

        self.output = ctk.CTkTextbox(term_wrap, font=ctk.CTkFont(family="Consolas", size=13),
                                      fg_color=BG, text_color=TEXT, wrap="none", state="disabled",
                                      corner_radius=0, scrollbar_button_color=GRAY)
        self.output.grid(row=1, column=0, sticky="nsew", padx=1, pady=(0,1))
        self.output.tag_config("open", foreground=GREEN)
        self.output.tag_config("info", foreground=CYAN)
        self.output.tag_config("error", foreground=RED)
        self.output.tag_config("head", foreground=CYAN_DIM)

        # progress bar
        self.progress = ctk.CTkProgressBar(self, height=5, corner_radius=0, progress_color=CYAN, fg_color=BG3)
        self.progress.grid(row=4, column=0, sticky="ew", padx=0)
        self.progress.set(0)

        # footer buttons
        foot = tk.Frame(self, bg=BG)
        foot.grid(row=5, column=0, padx=20, pady=12, sticky="ew")

        self.scan_btn = ctk.CTkButton(foot, text="▶  START SCAN", width=160, height=42,
                                       font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
                                       fg_color="#0d3a5c", hover_color="#0f4a78",
                                       text_color=CYAN, border_width=1, border_color=CYAN,
                                       corner_radius=6, command=self._toggle_scan)
        self.scan_btn.pack(side="left")

        ctk.CTkButton(foot, text="Clear", width=80, height=42,
                      font=ctk.CTkFont(family="Consolas", size=12),
                      fg_color=BG3, hover_color=ACCENT, text_color=GRAY_LT,
                      border_width=1, border_color=GRAY, corner_radius=6,
                      command=self._clear).pack(side="left", padx=(10,0))

        ctk.CTkButton(foot, text="Copy", width=80, height=42,
                      font=ctk.CTkFont(family="Consolas", size=12),
                      fg_color=BG3, hover_color=ACCENT, text_color=GRAY_LT,
                      border_width=1, border_color=GRAY, corner_radius=6,
                      command=self._copy).pack(side="left", padx=(8,0))

        GlowButton(foot, text="⬡  Product of Vayro", btn_width=178, btn_height=38, layers=10).pack(side="right")

    # --------------------------------------------------------
    # helpers
    # --------------------------------------------------------
    def _log(self, text, tag=""):
        self.output.configure(state="normal")
        self.output.insert("end", text, tag)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _clear(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.progress.set(0)
        self.open_count = 0
        self.closed_count = 0
        self.open_card.set("0")
        self.closed_card.set("0")

    def _copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.output.get("1.0", "end"))
        self.status_label.configure(text="● COPIED", fg=GREEN)
        self.after(1800, lambda: self.status_label.configure(
            text="● IDLE" if not self.scanning else "● SCANNING",
            fg=CYAN if self.scanning else GRAY_LT))

    # --------------------------------------------------------
    # scan control
    # --------------------------------------------------------
    def _toggle_scan(self):
        if self.scanning:
            self.stop_event.set()
            self.scan_btn.configure(text="▶  START SCAN", fg_color="#0d3a5c", text_color=CYAN, border_color=CYAN)
            self.scanning = False
            self.status_label.configure(text="● STOPPED", fg=AMBER)
        else:
            self._start_scan()

    def _start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            self._log("[error] enter a target\n", "error")
            return
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            self._log(f"[error] cannot resolve {target}\n", "error")
            return

        threads = int(self.threads_var.get())
        self.open_count = 0
        self.closed_count = 0
        self.scanning = True
        self.stop_event.clear()
        self.start_time = datetime.now()
        self.progress.set(0)
        self.open_card.set("0")
        self.closed_card.set("0")

        self.scan_btn.configure(text="■  STOP SCAN", fg_color="#3a0d0d", text_color=RED, border_color=RED)
        self.status_label.configure(text="● SCANNING", fg=CYAN)

        ts = datetime.now().strftime("%H:%M:%S")
        self._log(f"\n┌{'─'*54}┐\n", "head")
        self._log(f"│  VayroScan  ·  {ts:<39}│\n", "head")
        self._log(f"│  Target  : {target} ({ip}){' ' * max(0,38-len(target)-len(ip))}│\n", "head")
        self._log(f"│  Range   : {PORT_START}–{PORT_END} ({self.total_ports} ports)│\n", "head")
        self._log(f"│  Threads : {threads:<3}   Timeout : {TIMEOUT}s{' ' * 24}│\n", "head")
        self._log(f"└{'─'*54}┘\n\n", "head")

        # fill queue with all ports
        port_queue = Queue()
        for p in range(PORT_START, PORT_END+1):
            port_queue.put(p)

        def worker():
            while not self.stop_event.is_set():
                try:
                    port = port_queue.get_nowait()
                except Empty:
                    break
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(TIMEOUT)
                    is_open = (sock.connect_ex((ip, port)) == 0)
                    sock.close()
                except:
                    is_open = False
                self.result_queue.put(("result", port, is_open))

        def runner():
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = [pool.submit(worker) for _ in range(threads)]
                for f in futures:
                    f.result()
            self.result_queue.put(("done", ip, target))

        threading.Thread(target=runner, daemon=True).start()

    # --------------------------------------------------------
    # poll results from queue
    # --------------------------------------------------------
    def _poll_queue(self):
        try:
            processed = 0
            while processed < 200:
                msg = self.result_queue.get_nowait()
                processed += 1

                if msg[0] == "result":
                    _, port, is_open = msg
                    if is_open:
                        self.open_count += 1
                        svc = SERVICES.get(port, "unknown")
                        self._log(f"  [OPEN]  {port:<6}  {svc}\n", "open")
                    else:
                        self.closed_count += 1

                    done = self.open_count + self.closed_count
                    self.progress.set(done / max(self.total_ports, 1))
                    self.open_card.set(self.open_count)
                    self.closed_card.set(self.closed_count)

                elif msg[0] == "done":
                    _, ip, target = msg
                    self.scanning = False
                    self.scan_btn.configure(text="▶  START SCAN", fg_color="#0d3a5c", text_color=CYAN, border_color=CYAN)
                    self.progress.set(1.0)
                    elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
                    self.status_label.configure(text="● DONE", fg=GREEN)
                    self._log(f"\n┌{'─'*54}┐\n", "head")
                    self._log(f"│  Scan complete  ·  {elapsed:.2f}s{' ' * max(0,34 - len(f'{elapsed:.2f}'))}│\n", "head")
                    self._log(f"│  {self.open_count} open port(s) on {target} ({ip}){' ' * max(0,36-len(str(self.open_count))-len(target)-len(ip))}│\n", "head")
                    self._log(f"└{'─'*54}┘\n", "head")

        except Empty:
            pass
        self.after(50, self._poll_queue)


# ------------------------------------------------------------
# run
# ------------------------------------------------------------
if __name__ == "__main__":
    app = VayroScan()
    app.mainloop()