#!/usr/bin/env python3
"""
qmrClau - Gestor de Contrasenyes Portable
Un gestor de contrasenyes local, xifrat i portable per a Windows/Linux.
Suport de grups i subgrups jeràrquics (arbre il·limitat).
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import ftplib
import http.server
import json
import socket
import tempfile
import threading
import urllib.parse
import urllib.request
import urllib.error
import webbrowser
import os
import sys
import base64
import hashlib
import hmac
import secrets
import string
import struct
import time
import shutil
import uuid
from datetime import datetime


# --- Configuració ---

CONFIG_FILENAME = "qmrclau.json"

def _get_config_path():
    """Retorna la ruta del fitxer de configuració, al costat de l'executable o script."""
    if getattr(sys, 'frozen', False):
        # Executable (PyInstaller)
        base_dir = os.path.dirname(sys.executable)
    else:
        # Script Python
        base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, CONFIG_FILENAME)

def load_config() -> dict:
    """Carrega la configuració. Si no existeix, la crea amb valors per defecte."""
    defaults = {
        "last_db_path": "",
        "ftp_last": {},
        "gdrive_credentials": {},
        "gdrive_last_filename": "mydb.vkdb",
    }
    path = _get_config_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Assegurar que totes les claus per defecte existeixen
            for k, v in defaults.items():
                if k not in data:
                    data[k] = v
            return data
        except Exception:
            pass
    # Crear config per defecte
    save_config(defaults)
    return dict(defaults)

def save_config(config: dict):
    """Desa la configuració a disc."""
    path = _get_config_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
    except Exception:
        pass  # Si no es pot escriure (p.ex. directori de només lectura), no passa res

# --- Criptografia (AES-256-CBC + PBKDF2 purs en Python, sense dependències) ---

def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    dk = b""
    block_num = 1
    while len(dk) < dklen:
        u = hmac.new(password, salt + struct.pack(">I", block_num), hashlib.sha256).digest()
        result = u
        for _ in range(iterations - 1):
            u = hmac.new(password, u, hashlib.sha256).digest()
            result = bytes(a ^ b for a, b in zip(result, u))
        dk += result
        block_num += 1
    return dk[:dklen]

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

def _mix_single(a, b, c, d):
    t = a ^ b ^ c ^ d
    return [a ^ t ^ _xtime(a ^ b), b ^ t ^ _xtime(b ^ c),
            c ^ t ^ _xtime(c ^ d), d ^ t ^ _xtime(d ^ a)]

def _inv_mix_single(a, b, c, d):
    u = _xtime(_xtime(a ^ c)); v = _xtime(_xtime(b ^ d))
    a ^= u; b ^= v; c ^= u; d ^= v
    return _mix_single(a, b, c, d)

def _key_expansion(key: bytes):
    nk = len(key) // 4; nr = nk + 6; w = []
    for i in range(nk):
        w.append(list(key[4*i:4*i+4]))
    for i in range(nk, 4*(nr+1)):
        temp = list(w[i-1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i//nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([a ^ b for a, b in zip(w[i-nk], temp)])
    round_keys = []
    for r in range(nr + 1):
        rk = []
        for c in range(4): rk.extend(w[r*4 + c])
        round_keys.append(rk)
    return round_keys, nr

def _aes_encrypt_block(block: bytes, round_keys, nr):
    state = [[block[r + 4*c] for r in range(4)] for c in range(4)]
    for c in range(4):
        for r in range(4): state[c][r] ^= round_keys[0][c*4+r]
    for rnd in range(1, nr+1):
        for c in range(4):
            for r in range(4): state[c][r] = _SBOX[state[c][r]]
        for r in range(1, 4):
            vals = [state[c][r] for c in range(4)]
            vals = vals[r:] + vals[:r]
            for c in range(4): state[c][r] = vals[c]
        if rnd < nr:
            for c in range(4): state[c] = _mix_single(*state[c])
        for c in range(4):
            for r in range(4): state[c][r] ^= round_keys[rnd][c*4+r]
    out = bytearray(16)
    for c in range(4):
        for r in range(4): out[r + 4*c] = state[c][r]
    return bytes(out)

def _aes_decrypt_block(block: bytes, round_keys, nr):
    state = [[block[r + 4*c] for r in range(4)] for c in range(4)]
    for c in range(4):
        for r in range(4): state[c][r] ^= round_keys[nr][c*4+r]
    for rnd in range(nr-1, -1, -1):
        for r in range(1, 4):
            vals = [state[c][r] for c in range(4)]
            vals = vals[-r:] + vals[:-r]
            for c in range(4): state[c][r] = vals[c]
        for c in range(4):
            for r in range(4): state[c][r] = _INV_SBOX[state[c][r]]
        for c in range(4):
            for r in range(4): state[c][r] ^= round_keys[rnd][c*4+r]
        if rnd > 0:
            for c in range(4): state[c] = _inv_mix_single(*state[c])
    out = bytearray(16)
    for c in range(4):
        for r in range(4): out[r + 4*c] = state[c][r]
    return bytes(out)

def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16: raise ValueError("Padding invàlid")
    if data[-pad_len:] != bytes([pad_len] * pad_len): raise ValueError("Padding invàlid")
    return data[:-pad_len]

def aes256_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    round_keys, nr = _key_expansion(key)
    padded = _pkcs7_pad(plaintext); ciphertext = b""; prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc = _aes_encrypt_block(block, round_keys, nr)
        ciphertext += enc; prev = enc
    return ciphertext

def aes256_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    round_keys, nr = _key_expansion(key)
    plaintext = b""; prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = _aes_decrypt_block(block, round_keys, nr)
        plaintext += bytes(a ^ b for a, b in zip(dec, prev)); prev = block
    return _pkcs7_unpad(plaintext)


# --- Gestió de la Base de Dades Xifrada ---

ITERATIONS = 200_000
DB_VERSION = 3

def derive_key(password: str, salt: bytes) -> bytes:
    return pbkdf2_sha256(password.encode("utf-8"), salt, ITERATIONS, 32)

def encrypt_db(data: dict, password: str) -> bytes:
    salt = secrets.token_bytes(32); iv = secrets.token_bytes(16)
    key = derive_key(password, salt)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ct = aes256_cbc_encrypt(plaintext, key, iv)
    mac = hmac.new(key, salt + iv + ct, hashlib.sha256).digest()
    header = struct.pack(">4sH", b"VKDB", DB_VERSION)
    return header + salt + iv + mac + ct

def decrypt_db(blob: bytes, password: str) -> dict:
    if len(blob) < 6 + 32 + 16 + 32: raise ValueError("Fitxer corrupte")
    magic, ver = struct.unpack(">4sH", blob[:6])
    if magic != b"VKDB": raise ValueError("No és un fitxer qmrClau")
    if ver > DB_VERSION: raise ValueError(f"Versió {ver} no suportada")
    salt = blob[6:38]; iv = blob[38:54]; mac_stored = blob[54:86]; ct = blob[86:]
    key = derive_key(password, salt)
    mac_calc = hmac.new(key, salt + iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_stored, mac_calc):
        raise ValueError("Contrasenya incorrecta o fitxer corrupte")
    plaintext = aes256_cbc_decrypt(ct, key, iv)
    data = json.loads(plaintext.decode("utf-8"))
    if ver <= 2 or ("groups" in data and isinstance(data["groups"], list) and
                     len(data["groups"]) > 0 and "id" not in data["groups"][0]):
        data = _migrate_v2_to_v3(data)
    return data


# --- Estructura de Grups Jeràrquics ---

def _make_group(name, entries=None, children=None):
    return {"id": str(uuid.uuid4()), "name": name,
            "entries": entries or [], "children": children or []}

def _new_db_data():
    now = datetime.now().isoformat()
    return {
        "root": _make_group("Arrel", children=[
            _make_group("General"), _make_group("Correu electrònic"),
            _make_group("Xarxes socials"), _make_group("Banca"),
        ]),
        "meta": {"created": now, "modified": now, "version": DB_VERSION},
    }

def _migrate_v2_to_v3(data):
    old_groups = data.get("groups", [])
    children = []
    for g in old_groups:
        children.append(_make_group(g.get("name", "Sense nom"), entries=g.get("entries", [])))
    if not children: children = [_make_group("General")]
    return {"root": _make_group("Arrel", children=children), "meta": data.get("meta", {})}

def find_group_by_id(root, group_id):
    if root["id"] == group_id: return root
    for child in root.get("children", []):
        found = find_group_by_id(child, group_id)
        if found: return found
    return None

def find_parent_of(root, group_id):
    for child in root.get("children", []):
        if child["id"] == group_id: return root
        found = find_parent_of(child, group_id)
        if found: return found
    return None

def count_entries_recursive(group):
    total = len(group.get("entries", []))
    for child in group.get("children", []):
        total += count_entries_recursive(child)
    return total

def collect_all_groups(root, result=None):
    if result is None: result = []
    result.append(root)
    for child in root.get("children", []):
        collect_all_groups(child, result)
    return result

def get_group_path(root, group_id, path=None):
    if path is None: path = []
    path.append(root["name"])
    if root["id"] == group_id: return " / ".join(path)
    for child in root.get("children", []):
        result = get_group_path(child, group_id, list(path))
        if result: return result
    return None

def get_descendants(g):
    ids = {g["id"]}
    for c in g.get("children", []): ids |= get_descendants(c)
    return ids


# --- Generador de Contrasenyes ---

def generate_password(length=20, upper=True, lower=True, digits=True, symbols=True):
    chars = ""; required = []
    if upper: chars += string.ascii_uppercase; required.append(secrets.choice(string.ascii_uppercase))
    if lower: chars += string.ascii_lowercase; required.append(secrets.choice(string.ascii_lowercase))
    if digits: chars += string.digits; required.append(secrets.choice(string.digits))
    if symbols:
        syms = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        chars += syms; required.append(secrets.choice(syms))
    if not chars: chars = string.ascii_letters + string.digits
    rest = [secrets.choice(chars) for _ in range(length - len(required))]
    pwd_list = required + rest
    for i in range(len(pwd_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pwd_list[i], pwd_list[j] = pwd_list[j], pwd_list[i]
    return "".join(pwd_list)

def password_strength(pwd):
    score = 0; l = len(pwd)
    if l >= 8: score += 15
    if l >= 12: score += 15
    if l >= 16: score += 10
    if l >= 20: score += 10
    if any(c.isupper() for c in pwd): score += 10
    if any(c.islower() for c in pwd): score += 10
    if any(c.isdigit() for c in pwd): score += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in pwd): score += 10
    unique = len(set(pwd))
    if unique > 6: score += 5
    if unique > 10: score += 5
    score = min(100, score)
    if score < 30: text = "Molt feble"
    elif score < 50: text = "Feble"
    elif score < 70: text = "Acceptable"
    elif score < 90: text = "Forta"
    else: text = "Molt forta"
    return score, text


# --- Colors i Tema ---

COLORS = {
    "bg": "#1a1b2e", "bg_secondary": "#232440", "bg_entry": "#2a2b4a",
    "accent": "#6c63ff", "accent_hover": "#5a52e0", "accent_light": "#8b83ff",
    "text": "#e8e6f0", "text_dim": "#9490b0", "text_dark": "#1a1b2e",
    "success": "#4ecdc4", "warning": "#ffe66d", "danger": "#ff6b6b",
    "border": "#3a3b5a", "sidebar_bg": "#15162a", "sidebar_hover": "#2a2b4a",
    "sidebar_active": "#6c63ff", "card_bg": "#232440",
    "strength_weak": "#ff6b6b", "strength_medium": "#ffe66d", "strength_strong": "#4ecdc4",
    "tree_bg": "#15162a", "tree_selected": "#6c63ff",
}


# --- Tooltip ---

class Tooltip:
    def __init__(self, widget, text):
        self._widget = widget
        self._text = text
        self._win = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _show(self, event=None):
        if self._win:
            return
        self._win = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+10000+10000")  # fora de pantalla per mesurar
        tk.Label(tw, text=self._text, font=("Segoe UI", 9),
                 bg=COLORS["bg_secondary"], fg=COLORS["text"],
                 relief="flat", bd=0, padx=8, pady=4).pack()
        tw.update_idletasks()
        tw_w = tw.winfo_width()
        tw_h = tw.winfo_height()
        scr_w = tw.winfo_screenwidth()
        scr_h = tw.winfo_screenheight()
        x = self._widget.winfo_rootx() + self._widget.winfo_width() // 2
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        x = max(4, min(x, scr_w - tw_w - 4))
        y = max(4, min(y, scr_h - tw_h - 4))
        tw.wm_geometry(f"+{x}+{y}")

    def _hide(self, event=None):
        if self._win:
            self._win.destroy()
            self._win = None


# --- Aplicació Principal ---

class QmrClauApp:
    def __init__(self, root):
        self.root = root
        self.root.title("qmrClau")
        self.root.geometry("1020x660")
        self.root.minsize(840, 540)
        self.root.configure(bg=COLORS["bg"])
        self.db_path = None
        self.master_password = None
        self.data = None
        self.ftp_config = None
        self.gdrive_file_id = None
        self.gdrive_filename = None
        self.current_group_id = None
        self.unsaved_changes = False
        self.clipboard_clear_id = None
        self.config = load_config()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._setup_styles()
        self._show_welcome()

    def _setup_styles(self):
        style = ttk.Style(); style.theme_use("clam")
        style.configure(".", background=COLORS["bg"], foreground=COLORS["text"],
                        fieldbackground=COLORS["bg_entry"])
        style.configure("Groups.Treeview", background=COLORS["tree_bg"],
                        foreground=COLORS["text"], fieldbackground=COLORS["tree_bg"],
                        font=("Segoe UI", 10), rowheight=28, borderwidth=0, relief="flat")
        style.map("Groups.Treeview",
                    background=[("selected", COLORS["tree_selected"])],
                    foreground=[("selected", "#ffffff")])
        style.layout("Groups.Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])

    # ---- Pantalla de Benvinguda ----
    def _show_welcome(self):
        self._clear_root()
        frame = tk.Frame(self.root, bg=COLORS["bg"])
        frame.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(frame, text="🔐", font=("Segoe UI", 48), bg=COLORS["bg"]).pack(pady=(0, 8))
        tk.Label(frame, text="qmrClau", font=("Segoe UI", 28, "bold"),
                fg=COLORS["accent_light"], bg=COLORS["bg"]).pack()
        tk.Label(frame, text="Gestor de Contrasenyes Portable",
                font=("Segoe UI", 12), fg=COLORS["text_dim"], bg=COLORS["bg"]).pack(pady=(2, 30))
        btn_frame = tk.Frame(frame, bg=COLORS["bg"]); btn_frame.pack()
        self._make_button(btn_frame, "📁  Crear Nova Base de Dades", self._new_db,
                        COLORS["accent"], width=28).pack(pady=5)
        self._make_button(btn_frame, "🔓  Obrir Base de Dades", self._open_db,
                        COLORS["bg_entry"], width=28).pack(pady=5)
        self._make_button(btn_frame, "🌐  Obrir des de FTP", self._open_ftp_db,
                        COLORS["bg_entry"], width=28).pack(pady=5)
        self._make_button(btn_frame, "☁️  Obrir des de Google Drive", self._open_gdrive_db,
                        COLORS["bg_entry"], width=28).pack(pady=5)

        # Botó obrir darrera BD (només si existeix una ruta vàlida)
        last_path = self.config.get("last_db_path", "")
        if last_path and os.path.exists(last_path):
            last_name = os.path.splitext(os.path.basename(last_path))[0]
            self._make_button(btn_frame, f"🕐  Obrir darrera: {last_name}",
                                self._open_last_db, COLORS["bg_secondary"], width=28).pack(pady=5)
            tk.Label(frame, text=last_path, font=("Segoe UI", 8),
                        fg=COLORS["text_dim"], bg=COLORS["bg"]).pack(pady=(2, 0))

        tk.Label(frame, text="AES-256 · PBKDF2-SHA256 · 200k iteracions",
                    font=("Segoe UI", 9), fg=COLORS["text_dim"], bg=COLORS["bg"]).pack(pady=(24, 0))

    def _make_button(self, parent, text, command, bg_color, width=16, fg_color=None):
        fg = fg_color or COLORS["text"]
        return tk.Button(parent, text=text, command=command, font=("Segoe UI", 11),
                        bg=bg_color, fg=fg, activebackground=COLORS["accent_hover"],
                        activeforeground="#fff", relief="flat", cursor="hand2",
                        width=width, pady=8, bd=0)

    def _make_small_button(self, parent, text, command, bg_color=None):
        bg = bg_color or COLORS["bg_entry"]
        return tk.Button(parent, text=text, command=command, font=("Segoe UI", 9),
                        bg=bg, fg=COLORS["text"], activebackground=COLORS["accent"],
                        activeforeground="#fff", relief="flat", cursor="hand2",
                        bd=0, padx=10, pady=3)

    def _tip(self, widget, text):
        Tooltip(widget, text)

    def _center_dialog(self, dialog, width, height):
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - width) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - height) // 2
        dialog.geometry(f"{width}x{height}+{x}+{y}")

    def _ask_text_dialog(self, title, prompt, initial_value=""):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg=COLORS["bg"])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        self._center_dialog(dialog, 380, 170)
        result = {"value": None}
        tk.Label(dialog, text=prompt, font=("Segoe UI", 12, "bold"),
                fg=COLORS["accent_light"], bg=COLORS["bg"]).pack(pady=(20, 8))
        entry = tk.Entry(dialog, font=("Segoe UI", 11), bg=COLORS["bg_entry"],
                        fg=COLORS["text"], insertbackground=COLORS["text"],
                        relief="flat", bd=0)
        entry.pack(fill="x", padx=30, pady=(0, 12), ipady=6)
        if initial_value:
            entry.insert(0, initial_value)
            entry.select_range(0, "end")
        entry.focus_set()
        def submit(event=None):
            val = entry.get().strip()
            if val:
                result["value"] = val
            dialog.destroy()
        entry.bind("<Return>", submit)
        entry.bind("<Escape>", lambda e: dialog.destroy())
        bf = tk.Frame(dialog, bg=COLORS["bg"])
        bf.pack()
        self._make_button(bf, "Acceptar", submit, COLORS["accent"], width=10).pack(side="left", padx=(0, 8))
        self._make_button(bf, "Cancel·lar", dialog.destroy, COLORS["bg_entry"], width=10).pack(side="left")
        dialog.wait_window()
        return result["value"]

    # ---- Crear / Obrir DB ----
    def _save_last_db_path(self, path):
        """Desa la ruta de la darrera BD oberta a la configuració."""
        self.config["last_db_path"] = path
        save_config(self.config)

    def _new_db(self):
        path = filedialog.asksaveasfilename(title="Crear nova base de dades",
            defaultextension=".vkdb", filetypes=[("qmrClau DB", "*.vkdb"), ("Tots", "*.*")])
        if not path: return
        pwd = self._ask_password("Crea la contrasenya mestra", confirm=True)
        if not pwd: return
        self.db_path = path; self.master_password = pwd
        self.data = _new_db_data()
        self.current_group_id = self.data["root"]["children"][0]["id"]
        self._save_db()
        self._save_last_db_path(path)
        self._show_main()

    def _open_db(self):
        path = filedialog.askopenfilename(title="Obrir base de dades",
            filetypes=[("qmrClau DB", "*.vkdb"), ("Tots", "*.*")])
        if not path: return
        self._open_db_from_path(path)

    def _open_last_db(self):
        last_path = self.config.get("last_db_path", "")
        if not last_path or not os.path.exists(last_path):
            messagebox.showwarning("Avís", "El fitxer ja no existeix.", parent=self.root)
            return
        self._open_db_from_path(last_path)

    def _open_db_from_path(self, path):
        pwd = self._ask_password("Introdueix la contrasenya mestra")
        if not pwd: return
        try:
            with open(path, "rb") as f: blob = f.read()
            self.data = decrypt_db(blob, pwd)
            if "root" not in self.data: self.data = _migrate_v2_to_v3(self.data)
        except ValueError as e:
            messagebox.showerror("Error", str(e)); return
        except Exception as e:
            messagebox.showerror("Error", f"No s'ha pogut obrir: {e}"); return
        self.db_path = path; self.master_password = pwd
        root = self.data["root"]
        self.current_group_id = root["children"][0]["id"] if root.get("children") else root["id"]
        self._save_last_db_path(path)
        self._show_main()

    def _ask_password(self, title, confirm=False):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg=COLORS["bg"]); dialog.resizable(False, False)
        dialog.transient(self.root); dialog.grab_set()
        self._center_dialog(dialog, 400, 240 if confirm else 180)
        result = {"pwd": None}
        tk.Label(dialog, text=title, font=("Segoe UI", 13, "bold"),
                fg=COLORS["accent_light"], bg=COLORS["bg"]).pack(pady=(18, 12))
        tk.Label(dialog, text="Contrasenya mestra:", font=("Segoe UI", 10),
                fg=COLORS["text_dim"], bg=COLORS["bg"]).pack(anchor="w", padx=30)
        pwd_entry = tk.Entry(dialog, show="●", font=("Segoe UI", 12),
                            bg=COLORS["bg_entry"], fg=COLORS["text"],
                            insertbackground=COLORS["text"], relief="flat", bd=0)
        pwd_entry.pack(fill="x", padx=30, pady=(2, 8), ipady=6); pwd_entry.focus_set()
        confirm_entry = None
        if confirm:
            tk.Label(dialog, text="Confirma la contrasenya:", font=("Segoe UI", 10),
                    fg=COLORS["text_dim"], bg=COLORS["bg"]).pack(anchor="w", padx=30)
            confirm_entry = tk.Entry(dialog, show="●", font=("Segoe UI", 12),
                                    bg=COLORS["bg_entry"], fg=COLORS["text"],
                                    insertbackground=COLORS["text"], relief="flat", bd=0)
            confirm_entry.pack(fill="x", padx=30, pady=(2, 8), ipady=6)
        def submit(event=None):
            p = pwd_entry.get()
            if not p:
                messagebox.showwarning("Avís", "La contrasenya no pot ser buida.", parent=dialog); return
            if confirm:
                if p != confirm_entry.get():
                    messagebox.showwarning("Avís", "Les contrasenyes no coincideixen.", parent=dialog); return
                if len(p) < 6:
                    messagebox.showwarning("Avís", "Mínim 6 caràcters.", parent=dialog); return
            result["pwd"] = p; dialog.destroy()
        pwd_entry.bind("<Return>", lambda e: (confirm_entry.focus_set() if confirm else submit(e)))
        if confirm_entry: confirm_entry.bind("<Return>", submit)
        self._make_button(dialog, "Acceptar", submit, COLORS["accent"], width=14).pack(pady=(6, 0))
        dialog.wait_window(); return result["pwd"]

    # ---- Desar ----
    def _save_db(self):
        if not self.db_path or not self.master_password: return
        self.data["meta"]["modified"] = datetime.now().isoformat()
        blob = encrypt_db(self.data, self.master_password)
        tmp = self.db_path + ".tmp"
        with open(tmp, "wb") as f: f.write(blob)
        shutil.move(tmp, self.db_path)
        self.unsaved_changes = False; self._update_title()
        if self.ftp_config:
            try:
                self._ftp_upload(self.ftp_config, self.db_path)
            except Exception as e:
                messagebox.showwarning("Avís FTP",
                    f"Desat localment però no s'ha pogut pujar al FTP:\n{e}", parent=self.root)
        if self.gdrive_file_id:
            try:
                token = self._gdrive_token()
                if not token: raise Exception("No s'ha pogut obtenir el token d'accés")
                self._gdrive_upload_update(token, self.gdrive_file_id, self.db_path)
            except Exception as e:
                messagebox.showwarning("Avís Drive",
                    f"Desat localment però no s'ha pogut pujar a Drive:\n{e}", parent=self.root)

    # ---- Interfície Principal ----
    def _clear_root(self):
        for w in self.root.winfo_children(): w.destroy()

    def _update_title(self):
        if self.gdrive_file_id:
            name = f"☁️ Drive: {self.gdrive_filename}"
        elif self.ftp_config:
            name = f"🌐 {self.ftp_config['host']}{self.ftp_config['path']}"
        elif self.db_path:
            name = os.path.basename(self.db_path)
        else:
            name = "qmrClau"
        mod = " ●" if self.unsaved_changes else ""
        self.root.title(f"qmrClau — {name}{mod}")

    def _show_main(self):
        self._clear_root(); self._update_title()

        # Toolbar
        toolbar = tk.Frame(self.root, bg=COLORS["bg_secondary"], height=42)
        toolbar.pack(fill="x"); toolbar.pack_propagate(False)
        tb_left = tk.Frame(toolbar, bg=COLORS["bg_secondary"]); tb_left.pack(side="left", padx=8)
        btn_save = self._make_small_button(tb_left, "💾 Desar", self._save_db, COLORS["bg_entry"])
        btn_save.pack(side="left", padx=2, pady=6); self._tip(btn_save, "Desar la base de dades (Ctrl+S)")
        btn_lock = self._make_small_button(tb_left, "🔒 Tancar", self._lock_db, COLORS["bg_entry"])
        btn_lock.pack(side="left", padx=2, pady=6); self._tip(btn_lock, "Bloquejar i tancar la base de dades")
        btn_pwd = self._make_small_button(tb_left, "🔑 Canviar Contrasenya", self._change_master_password, COLORS["bg_entry"])
        btn_pwd.pack(side="left", padx=2, pady=6); self._tip(btn_pwd, "Canviar la contrasenya mestra")
        tb_right = tk.Frame(toolbar, bg=COLORS["bg_secondary"]); tb_right.pack(side="right", padx=8)
        btn_gen = self._make_small_button(tb_right, "⚡ Generador", self._show_password_generator, COLORS["accent"])
        btn_gen.pack(side="right", padx=2, pady=6); self._tip(btn_gen, "Obrir el generador de contrasenyes")
        btn_exp = self._make_small_button(tb_right, "📤 Exportar", self._export_csv, COLORS["bg_entry"])
        btn_exp.pack(side="right", padx=2, pady=6); self._tip(btn_exp, "Exportar totes les entrades a CSV (text pla)")
        btn_imp = self._make_small_button(tb_right, "📥 Importar", self._import_csv, COLORS["bg_entry"])
        btn_imp.pack(side="right", padx=2, pady=6); self._tip(btn_imp, "Importar entrades des d'un fitxer CSV")

        # Cerca global a la toolbar
        tb_center = tk.Frame(toolbar, bg=COLORS["bg_secondary"]); tb_center.pack(side="left", padx=(16, 8), fill="x", expand=True)
        search_container = tk.Frame(tb_center, bg=COLORS["bg_entry"], highlightbackground=COLORS["border"], highlightthickness=1)
        search_container.pack(side="left", fill="x", expand=True, pady=7)
        tk.Label(search_container, text="🔍", font=("Segoe UI", 9), bg=COLORS["bg_entry"],
                fg=COLORS["text_dim"]).pack(side="left", padx=(6, 0))
        self.global_search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_container, textvariable=self.global_search_var,
                                    font=("Segoe UI", 10), bg=COLORS["bg_entry"], fg=COLORS["text"],
                                    insertbackground=COLORS["text"], relief="flat", bd=0)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=4, ipady=2)
        self.search_entry.bind("<Return>", lambda e: self._do_global_search())
        self.search_entry.bind("<Escape>", lambda e: self._clear_search())
        self.search_clear_btn = self._make_small_button(search_container, "✕", self._clear_search, COLORS["bg_entry"])
        self.search_clear_btn.pack(side="right", padx=(0, 4))
        self.search_clear_btn.pack_forget()  # amagar fins que hi hagi cerca
        self.global_search_var.trace_add("write", self._on_search_changed)
        self._search_active = False

        body = tk.Frame(self.root, bg=COLORS["bg"]); body.pack(fill="both", expand=True)

        # Sidebar amb Treeview
        sidebar = tk.Frame(body, bg=COLORS["sidebar_bg"], width=250)
        sidebar.pack(side="left", fill="y"); sidebar.pack_propagate(False)

        sidebar_header = tk.Frame(sidebar, bg=COLORS["sidebar_bg"])
        sidebar_header.pack(fill="x", padx=8, pady=(10, 4))
        tk.Label(sidebar_header, text="GRUPS", font=("Segoe UI", 9, "bold"),
                fg=COLORS["text_dim"], bg=COLORS["sidebar_bg"]).pack(side="left")
        btn_subgrp = self._make_small_button(sidebar_header, "+ Subgrup", self._add_subgroup, COLORS["sidebar_bg"])
        btn_subgrp.pack(side="right"); self._tip(btn_subgrp, "Afegir un nou subgrup")

        tree_frame = tk.Frame(sidebar, bg=COLORS["tree_bg"])
        tree_frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self.tree = ttk.Treeview(tree_frame, style="Groups.Treeview", show="tree", selectmode="browse")
        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-3>", self._on_tree_right_click)
        # Linux right-click
        self.tree.bind("<Button-2>", self._on_tree_right_click)
        # Doble-clic per reanomenar
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        # Content
        self.content = tk.Frame(body, bg=COLORS["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        self._refresh_tree(); self._refresh_entries()

    # ---- Arbre de Grups (Treeview) ----
    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        self._tree_id_map = {}; self._group_to_tree = {}
        self._insert_tree_node("", self.data["root"])
        self._expand_all("")
        if self.current_group_id and self.current_group_id in self._group_to_tree:
            tid = self._group_to_tree[self.current_group_id]
            self.tree.selection_set(tid); self.tree.see(tid)

    def _insert_tree_node(self, parent_tree_id, group):
        count = count_entries_recursive(group)
        display = f"{group['name']}  ({count})"
        tid = self.tree.insert(parent_tree_id, "end", text=display, open=True)
        self._tree_id_map[tid] = group["id"]
        self._group_to_tree[group["id"]] = tid
        for child in group.get("children", []):
            self._insert_tree_node(tid, child)

    def _expand_all(self, item):
        for child in self.tree.get_children(item):
            self.tree.item(child, open=True)
            self._expand_all(child)

    def _on_tree_select(self, event):
        selected = self.tree.selection()
        if not selected: return
        gid = self._tree_id_map.get(selected[0])
        if gid and gid != self.current_group_id:
            self.current_group_id = gid; self._refresh_entries()

    def _on_tree_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item: return
        self.tree.selection_set(item)
        gid = self._tree_id_map.get(item)
        if not gid: return
        group = find_group_by_id(self.data["root"], gid)
        if not group: return
        is_root = (gid == self.data["root"]["id"])

        menu = tk.Menu(self.root, tearoff=0, bg=COLORS["bg_secondary"], fg=COLORS["text"],
                        activebackground=COLORS["accent"], font=("Segoe UI", 10))
        menu.add_command(label="Afegir subgrup", command=lambda: self._add_subgroup_to(gid))
        menu.add_command(label="Reanomenar", command=lambda: self._rename_group(gid))
        if not is_root:
            menu.add_separator()
            menu.add_command(label="Moure a...", command=lambda: self._move_group(gid))
            menu.add_separator()
            menu.add_command(label="Eliminar", command=lambda: self._delete_group(gid))
        menu.tk_popup(event.x_root, event.y_root)

    def _on_tree_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item: return
        gid = self._tree_id_map.get(item)
        if gid: self._rename_group(gid)

    def _add_subgroup(self):
        self._add_subgroup_to(self.current_group_id or self.data["root"]["id"])

    def _add_subgroup_to(self, parent_id):
        name = self._ask_text_dialog("Nou Subgrup", "Nom del subgrup:")
        if not name or not name.strip(): return
        parent = find_group_by_id(self.data["root"], parent_id)
        if not parent: return
        new_group = _make_group(name.strip())
        parent["children"].append(new_group)
        self.unsaved_changes = True
        self.current_group_id = new_group["id"]
        self._refresh_tree(); self._refresh_entries(); self._update_title()

    def _rename_group(self, gid):
        group = find_group_by_id(self.data["root"], gid)
        if not group: return
        name = self._ask_text_dialog("Reanomenar", "Nou nom:", initial_value=group["name"])
        if name and name.strip():
            group["name"] = name.strip()
            self.unsaved_changes = True
            self._refresh_tree(); self._refresh_entries(); self._update_title()

    def _delete_group(self, gid):
        if gid == self.data["root"]["id"]: return
        group = find_group_by_id(self.data["root"], gid)
        if not group: return
        total = count_entries_recursive(group)
        nch = len(group.get("children", []))
        msg = f"Eliminar «{group['name']}»"
        if total > 0: msg += f" amb {total} entrada/es"
        if nch > 0: msg += f" i {nch} subgrup/s"
        msg += "?\n\nAquesta acció és irreversible."
        if not messagebox.askyesno("Confirmar", msg, parent=self.root): return
        parent = find_parent_of(self.data["root"], gid)
        if parent: parent["children"] = [c for c in parent["children"] if c["id"] != gid]
        self.unsaved_changes = True
        if self.current_group_id == gid:
            self.current_group_id = parent["id"] if parent else self.data["root"]["id"]
        self._refresh_tree(); self._refresh_entries(); self._update_title()

    def _move_group(self, gid):
        if gid == self.data["root"]["id"]: return
        group = find_group_by_id(self.data["root"], gid)
        if not group: return
        dialog = tk.Toplevel(self.root); dialog.title("Moure grup")
        dialog.configure(bg=COLORS["bg"])
        dialog.resizable(False, False); dialog.transient(self.root); dialog.grab_set()
        self._center_dialog(dialog, 380, 420)
        tk.Label(dialog, text=f"Moure «{group['name']}» a:", font=("Segoe UI", 12, "bold"),
                    fg=COLORS["accent_light"], bg=COLORS["bg"]).pack(pady=(12, 8))
        excluded = get_descendants(group)
        all_groups = collect_all_groups(self.data["root"])
        valid = [g for g in all_groups if g["id"] not in excluded]
        listbox = tk.Listbox(dialog, font=("Segoe UI", 10), bg=COLORS["bg_entry"],
                                fg=COLORS["text"], selectbackground=COLORS["accent"],
                                selectforeground="#fff", relief="flat", bd=0, highlightthickness=0)
        listbox.pack(fill="both", expand=True, padx=16, pady=4)
        gmap = {}
        for g in valid:
            path = get_group_path(self.data["root"], g["id"]) or g["name"]
            listbox.insert("end", f"  {path}"); gmap[listbox.size() - 1] = g["id"]
        def do_move():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("Avís", "Selecciona un destí.", parent=dialog); return
            target_id = gmap[sel[0]]
            parent = find_parent_of(self.data["root"], gid)
            if parent: parent["children"] = [c for c in parent["children"] if c["id"] != gid]
            target = find_group_by_id(self.data["root"], target_id)
            if target: target["children"].append(group)
            self.unsaved_changes = True; dialog.destroy()
            self._refresh_tree(); self._refresh_entries(); self._update_title()
        self._make_button(dialog, "Moure aquí", do_move, COLORS["accent"], width=14).pack(pady=(4, 12))
        dialog.wait_window()

    # ---- Cerca Global ----
    def _on_search_changed(self, *_):
        query = self.global_search_var.get().strip()
        if query:
            self.search_clear_btn.pack(side="right", padx=(0, 4))
        else:
            self.search_clear_btn.pack_forget()
            if self._search_active:
                self._clear_search()

    def _do_global_search(self):
        query = self.global_search_var.get().strip().lower()
        if not query:
            self._clear_search(); return
        self._search_active = True
        self.search_clear_btn.pack(side="right", padx=(0, 4))
        # Cercar recursivament a tots els grups
        results = []
        self._search_recursive(self.data["root"], query, results)
        self._show_search_results(query, results)

    def _search_recursive(self, group, query, results):
        for i, entry in enumerate(group.get("entries", [])):
            t = entry.get("title", "").lower()
            u = entry.get("username", "").lower()
            url = entry.get("url", "").lower()
            notes = entry.get("notes", "").lower()
            if query in t or query in u or query in url or query in notes:
                results.append({"entry": entry, "entry_idx": i, "group": group})
        for child in group.get("children", []):
            self._search_recursive(child, query, results)

    def _show_search_results(self, query, results):
        for w in self.content.winfo_children(): w.destroy()

        header = tk.Frame(self.content, bg=COLORS["bg"])
        header.pack(fill="x", padx=16, pady=(12, 0))
        tk.Label(header, text=f"Resultats de cerca: «{query}»", font=("Segoe UI", 9),
                    fg=COLORS["text_dim"], bg=COLORS["bg"]).pack(anchor="w")

        header2 = tk.Frame(self.content, bg=COLORS["bg"])
        header2.pack(fill="x", padx=16, pady=(2, 8))
        tk.Label(header2, text=f"🔍 {len(results)} resultat/s", font=("Segoe UI", 16, "bold"),
                    fg=COLORS["text"], bg=COLORS["bg"]).pack(side="left")
        self._make_small_button(header2, "✕ Tancar cerca", self._clear_search,
                                COLORS["bg_entry"]).pack(side="right")

        self.entries_frame = tk.Frame(self.content, bg=COLORS["bg"])
        self.entries_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        canvas = tk.Canvas(self.entries_frame, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.entries_frame, orient="vertical", command=canvas.yview)
        self.entries_inner = tk.Frame(canvas, bg=COLORS["bg"])
        self.entries_inner.bind("<Configure>",
                                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.entries_inner, anchor="nw", tags="inner")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig("inner", width=e.width))
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        if not results:
            tk.Label(self.entries_inner,
                        text="No s'han trobat resultats.",
                        font=("Segoe UI", 11), fg=COLORS["text_dim"], bg=COLORS["bg"],
                        justify="center").pack(pady=60)
            return

        for r in results:
            self._make_search_result_card(r["entry"], r["entry_idx"], r["group"])

    def _make_search_result_card(self, entry, entry_idx, group):
        card = tk.Frame(self.entries_inner, bg=COLORS["card_bg"],
                        highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill="x", pady=3)
        inner = tk.Frame(card, bg=COLORS["card_bg"]); inner.pack(fill="x", padx=12, pady=8)
        top = tk.Frame(inner, bg=COLORS["card_bg"]); top.pack(fill="x")
        title = entry.get("title", "Sense títol")
        tk.Label(top, text=title, font=("Segoe UI", 11, "bold"),
                    fg=COLORS["text"], bg=COLORS["card_bg"], anchor="w").pack(side="left")
        # Botons: copiar i anar al grup
        bf = tk.Frame(top, bg=COLORS["card_bg"]); bf.pack(side="right")
        def copy_pwd():
            pwd = entry.get("password", "")
            self.root.clipboard_clear(); self.root.clipboard_append(pwd)
            if self.clipboard_clear_id: self.root.after_cancel(self.clipboard_clear_id)
            self.clipboard_clear_id = self.root.after(15000, self._clear_clipboard)
            messagebox.showinfo("Copiat", "Contrasenya copiada al portapapers.\nS'esborrarà en 15 segons.",
                                parent=self.root)
        def go_to_group():
            self._search_active = False
            self.global_search_var.set("")
            self.search_clear_btn.pack_forget()
            self.current_group_id = group["id"]
            if group["id"] in self._group_to_tree:
                self.tree.selection_set(self._group_to_tree[group["id"]])
                self.tree.see(self._group_to_tree[group["id"]])
            self._refresh_entries()
        btn_cpwd = self._make_small_button(bf, "📋", copy_pwd)
        btn_cpwd.pack(side="left", padx=2); self._tip(btn_cpwd, "Copiar contrasenya")
        btn_goto = self._make_small_button(bf, "📂 Anar al grup", go_to_group, COLORS["accent"])
        btn_goto.pack(side="left", padx=2); self._tip(btn_goto, "Navegar al grup d'aquesta entrada")
        # Detalls
        details = []
        if entry.get("username"): details.append(f"👤 {entry['username']}")
        if entry.get("url"): details.append(f"🌐 {entry['url']}")
        if details:
            tk.Label(inner, text="   ".join(details), font=("Segoe UI", 9),
                        fg=COLORS["text_dim"], bg=COLORS["card_bg"], anchor="w").pack(fill="x", pady=(2, 0))
        # Mostrar a quin grup pertany
        group_path = get_group_path(self.data["root"], group["id"]) or group["name"]
        tk.Label(inner, text=f"📁 {group_path}", font=("Segoe UI", 8),
                    fg=COLORS["accent_light"], bg=COLORS["card_bg"], anchor="w").pack(fill="x", pady=(2, 0))

    def _clear_search(self):
        self._search_active = False
        self.global_search_var.set("")
        self.search_clear_btn.pack_forget()
        self.search_entry.delete(0, "end")
        self._refresh_entries()

    # ---- Entrades ----
    def _get_current_group(self):
        if not self.data or not self.current_group_id: return None
        return find_group_by_id(self.data["root"], self.current_group_id)

    def _refresh_entries(self):
        for w in self.content.winfo_children(): w.destroy()
        group = self._get_current_group()
        if not group: return

        header = tk.Frame(self.content, bg=COLORS["bg"])
        header.pack(fill="x", padx=16, pady=(12, 0))
        path = get_group_path(self.data["root"], group["id"]) or group["name"]
        tk.Label(header, text=path, font=("Segoe UI", 9),
                    fg=COLORS["text_dim"], bg=COLORS["bg"]).pack(anchor="w")

        header2 = tk.Frame(self.content, bg=COLORS["bg"])
        header2.pack(fill="x", padx=16, pady=(2, 8))
        tk.Label(header2, text=group["name"], font=("Segoe UI", 16, "bold"),
                    fg=COLORS["text"], bg=COLORS["bg"]).pack(side="left")
        btn_ren = self._make_small_button(header2, "✏️", lambda: self._rename_group(group["id"]), COLORS["bg_entry"])
        btn_ren.pack(side="left", padx=(6, 0)); self._tip(btn_ren, "Reanomenar grup")
        btn_new = self._make_small_button(header2, "＋ Nova Entrada", self._add_entry, COLORS["accent"])
        btn_new.pack(side="right"); self._tip(btn_new, "Afegir una nova entrada")

        self.entries_frame = tk.Frame(self.content, bg=COLORS["bg"])
        self.entries_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        canvas = tk.Canvas(self.entries_frame, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.entries_frame, orient="vertical", command=canvas.yview)
        self.entries_inner = tk.Frame(canvas, bg=COLORS["bg"])
        self.entries_inner.bind("<Configure>",
                                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.entries_inner, anchor="nw", tags="inner")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig("inner", width=e.width))
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        self._filter_entries()

    def _filter_entries(self):
        for w in self.entries_inner.winfo_children(): w.destroy()
        group = self._get_current_group()
        if not group: return
        entries = group.get("entries", [])
        if not entries:
            tk.Label(self.entries_inner,
                        text="Cap entrada en aquest grup.\nFes clic a «＋ Nova Entrada» per començar.",
                        font=("Segoe UI", 11), fg=COLORS["text_dim"], bg=COLORS["bg"],
                        justify="center").pack(pady=60)
            return
        for i, entry in enumerate(entries):
            self._make_entry_card(i, entry)

    def _make_entry_card(self, idx, entry):
        card = tk.Frame(self.entries_inner, bg=COLORS["card_bg"], cursor="hand2",
                        highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill="x", pady=3)
        inner = tk.Frame(card, bg=COLORS["card_bg"]); inner.pack(fill="x", padx=12, pady=8)
        top = tk.Frame(inner, bg=COLORS["card_bg"]); top.pack(fill="x")
        title = entry.get("title", "Sense títol")
        title_lbl = tk.Label(top, text=title, font=("Segoe UI", 11, "bold"),
                                fg=COLORS["text"], bg=COLORS["card_bg"], anchor="w")
        title_lbl.pack(side="left")
        bf = tk.Frame(top, bg=COLORS["card_bg"]); bf.pack(side="right")
        btn_copy = self._make_small_button(bf, "📋", lambda i=idx: self._copy_password(i))
        btn_copy.pack(side="left", padx=2); self._tip(btn_copy, "Copiar contrasenya")
        btn_edit = self._make_small_button(bf, "✏️", lambda i=idx: self._edit_entry(i))
        btn_edit.pack(side="left", padx=2); self._tip(btn_edit, "Editar entrada")
        btn_move = self._make_small_button(bf, "📦", lambda i=idx: self._move_entry(i))
        btn_move.pack(side="left", padx=2); self._tip(btn_move, "Moure a un altre grup")
        btn_del = self._make_small_button(bf, "🗑️", lambda i=idx: self._delete_entry(i))
        btn_del.pack(side="left", padx=2); self._tip(btn_del, "Eliminar entrada")
        to_bind = [card, inner, top, title_lbl]
        details = []
        if entry.get("username"): details.append(f"👤 {entry['username']}")
        if entry.get("url"): details.append(f"🌐 {entry['url']}")
        if details:
            det_lbl = tk.Label(inner, text="   ".join(details), font=("Segoe UI", 9),
                                fg=COLORS["text_dim"], bg=COLORS["card_bg"], anchor="w")
            det_lbl.pack(fill="x", pady=(2, 0))
            to_bind.append(det_lbl)
        notes = entry.get("notes", "").strip()
        if notes:
            first_line = notes.split("\n")[0]
            preview = first_line[:80] + ("…" if len(first_line) > 80 or "\n" in notes else "")
            notes_lbl = tk.Label(inner, text=f"📝 {preview}", font=("Segoe UI", 9),
                                    fg=COLORS["text_dim"], bg=COLORS["card_bg"], anchor="w")
            notes_lbl.pack(fill="x", pady=(2, 0))
            to_bind.append(notes_lbl)
        edit_cmd = lambda e, i=idx: self._edit_entry(i)
        for w in to_bind:
            w.bind("<Double-Button-1>", edit_cmd)

    def _copy_password(self, idx):
        group = self._get_current_group()
        if not group: return
        pwd = group["entries"][idx].get("password", "")
        self.root.clipboard_clear(); self.root.clipboard_append(pwd)
        if self.clipboard_clear_id: self.root.after_cancel(self.clipboard_clear_id)
        self.clipboard_clear_id = self.root.after(15000, self._clear_clipboard)
        messagebox.showinfo("Copiat", "Contrasenya copiada al portapapers.\nS'esborrarà en 15 segons.",
                            parent=self.root)

    def _clear_clipboard(self):
        try: self.root.clipboard_clear(); self.root.clipboard_append("")
        except: pass

    def _add_entry(self): self._entry_dialog()

    def _edit_entry(self, idx):
        group = self._get_current_group()
        if group: self._entry_dialog(entry=group["entries"][idx], idx=idx)

    def _delete_entry(self, idx):
        group = self._get_current_group()
        if not group: return
        entry = group["entries"][idx]
        if messagebox.askyesno("Confirmar", f"Eliminar «{entry.get('title', '')}»?", parent=self.root):
            group["entries"].pop(idx); self.unsaved_changes = True
            self._refresh_tree(); self._refresh_entries(); self._update_title()

    def _move_entry(self, idx):
        group = self._get_current_group()
        if not group: return
        entry = group["entries"][idx]
        dialog = tk.Toplevel(self.root); dialog.title("Moure entrada")
        dialog.configure(bg=COLORS["bg"])
        dialog.resizable(False, False); dialog.transient(self.root); dialog.grab_set()
        self._center_dialog(dialog, 380, 420)
        tk.Label(dialog, text=f"Moure «{entry.get('title', '')}» a:", font=("Segoe UI", 12, "bold"),
                    fg=COLORS["accent_light"], bg=COLORS["bg"]).pack(pady=(12, 8))
        all_groups = collect_all_groups(self.data["root"])
        valid = [g for g in all_groups if g["id"] != self.current_group_id]
        listbox = tk.Listbox(dialog, font=("Segoe UI", 10), bg=COLORS["bg_entry"],
                                fg=COLORS["text"], selectbackground=COLORS["accent"],
                                selectforeground="#fff", relief="flat", bd=0, highlightthickness=0)
        listbox.pack(fill="both", expand=True, padx=16, pady=4)
        gmap = {}
        for g in valid:
            path = get_group_path(self.data["root"], g["id"]) or g["name"]
            listbox.insert("end", f"  {path}"); gmap[listbox.size() - 1] = g["id"]
        def do_move():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("Avís", "Selecciona un destí.", parent=dialog); return
            target = find_group_by_id(self.data["root"], gmap[sel[0]])
            if target:
                group["entries"].pop(idx); target["entries"].append(entry)
                self.unsaved_changes = True; dialog.destroy()
                self._refresh_tree(); self._refresh_entries(); self._update_title()
        self._make_button(dialog, "Moure aquí", do_move, COLORS["accent"], width=14).pack(pady=(4, 12))
        dialog.wait_window()

    def _entry_dialog(self, entry=None, idx=None):
        is_new = entry is None
        if is_new: entry = {"title": "", "username": "", "password": "", "url": "", "notes": ""}
        dialog = tk.Toplevel(self.root)
        dialog.title("Nova Entrada" if is_new else "Editar Entrada")
        dialog.configure(bg=COLORS["bg"])
        dialog.resizable(True, True); dialog.transient(self.root); dialog.grab_set()
        dialog.minsize(480, 540)
        self._center_dialog(dialog, 480, 580)
        fields = {}
        labels = [("Títol", "title"), ("Usuari", "username"), ("Contrasenya", "password"), ("URL", "url")]
        for i, (label, key) in enumerate(labels):
            tk.Label(dialog, text=label, font=("Segoe UI", 10), fg=COLORS["text_dim"],
                        bg=COLORS["bg"]).pack(anchor="w", padx=24, pady=(12 if i == 0 else 4, 0))
            frame = tk.Frame(dialog, bg=COLORS["bg"]); frame.pack(fill="x", padx=24, pady=(2, 0))
            show = "●" if key == "password" else None
            e = tk.Entry(frame, show=show, font=("Segoe UI", 11), bg=COLORS["bg_entry"],
                            fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", bd=0)
            e.pack(side="left", fill="x", expand=True, ipady=6)
            e.insert(0, entry.get(key, "")); fields[key] = e
            if key == "password":
                show_var = tk.BooleanVar(value=False)
                def toggle_show(ev=None, _e=e, _v=show_var):
                    _e.config(show="" if _v.get() else "●")
                tk.Checkbutton(frame, text="👁", variable=show_var, command=toggle_show,
                                bg=COLORS["bg"], fg=COLORS["text_dim"], selectcolor=COLORS["bg_entry"],
                                activebackground=COLORS["bg"], font=("Segoe UI", 10)).pack(side="left", padx=(4, 0))
                def gen_pwd(ev=None, _e=e):
                    p = generate_password(20); _e.delete(0, "end"); _e.insert(0, p); update_strength()
                btn_dice = self._make_small_button(frame, "🎲", gen_pwd, COLORS["accent"])
                btn_dice.pack(side="left", padx=(4, 0)); self._tip(btn_dice, "Generar contrasenya aleatòria")
                sf = tk.Frame(dialog, bg=COLORS["bg"]); sf.pack(fill="x", padx=24, pady=(4, 0))
                sc = tk.Canvas(sf, height=6, bg=COLORS["bg_entry"], highlightthickness=0); sc.pack(fill="x")
                sl = tk.Label(sf, text="", font=("Segoe UI", 9), fg=COLORS["text_dim"], bg=COLORS["bg"]); sl.pack(anchor="w")
                def update_strength(*_):
                    pwd = fields["password"].get(); score, text = password_strength(pwd)
                    sc.delete("all"); w = sc.winfo_width()
                    if w < 10: w = 430
                    fw = int(w * score / 100)
                    color = COLORS["strength_weak"] if score < 40 else COLORS["strength_medium"] if score < 70 else COLORS["strength_strong"]
                    sc.create_rectangle(0, 0, fw, 6, fill=color, outline=""); sl.config(text=text, fg=color)
                fields["password"].bind("<KeyRelease>", update_strength)
                dialog.after(100, update_strength)
        tk.Label(dialog, text="Notes", font=("Segoe UI", 10), fg=COLORS["text_dim"],
                    bg=COLORS["bg"]).pack(anchor="w", padx=24, pady=(8, 0))
        notes_text = tk.Text(dialog, height=6, font=("Segoe UI", 10), bg=COLORS["bg_entry"],
                                fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", bd=0, wrap="word")
        notes_text.pack(fill="both", expand=True, padx=24, pady=(2, 0))
        notes_text.insert("1.0", entry.get("notes", ""))
        bf = tk.Frame(dialog, bg=COLORS["bg"]); bf.pack(fill="x", padx=24, pady=(16, 12))
        def save():
            new_entry = {"title": fields["title"].get().strip(), "username": fields["username"].get().strip(),
                            "password": fields["password"].get(), "url": fields["url"].get().strip(),
                            "notes": notes_text.get("1.0", "end-1c").strip(), "modified": datetime.now().isoformat()}
            if not new_entry["title"]:
                messagebox.showwarning("Avís", "El títol és obligatori.", parent=dialog); return
            group = self._get_current_group()
            if not group: dialog.destroy(); return
            if is_new:
                new_entry["created"] = datetime.now().isoformat(); group["entries"].append(new_entry)
            else:
                new_entry["created"] = entry.get("created", datetime.now().isoformat()); group["entries"][idx] = new_entry
            self.unsaved_changes = True; dialog.destroy()
            self._refresh_tree(); self._refresh_entries(); self._update_title()
        self._make_button(bf, "💾  Desar", save, COLORS["accent"], width=12).pack(side="left", padx=(0, 8))
        self._make_button(bf, "Cancel·lar", dialog.destroy, COLORS["bg_entry"], width=12).pack(side="left")

    # ---- Generador ----
    def _show_password_generator(self):
        dialog = tk.Toplevel(self.root); dialog.title("Generador de Contrasenyes")
        dialog.configure(bg=COLORS["bg"])
        dialog.resizable(False, False); dialog.transient(self.root); dialog.grab_set()
        self._center_dialog(dialog, 440, 380)
        tk.Label(dialog, text="⚡ Generador", font=("Segoe UI", 16, "bold"),
                    fg=COLORS["accent_light"], bg=COLORS["bg"]).pack(pady=(16, 12))
        lf = tk.Frame(dialog, bg=COLORS["bg"]); lf.pack(fill="x", padx=24)
        tk.Label(lf, text="Longitud:", font=("Segoe UI", 10), fg=COLORS["text_dim"],
                    bg=COLORS["bg"]).pack(side="left")
        len_var = tk.IntVar(value=20)
        tk.Spinbox(lf, from_=4, to=128, textvariable=len_var, width=5, font=("Segoe UI", 11),
                    bg=COLORS["bg_entry"], fg=COLORS["text"],
                    buttonbackground=COLORS["bg_entry"]).pack(side="left", padx=8)
        upper_var = tk.BooleanVar(value=True); lower_var = tk.BooleanVar(value=True)
        digit_var = tk.BooleanVar(value=True); sym_var = tk.BooleanVar(value=True)
        cf = tk.Frame(dialog, bg=COLORS["bg"]); cf.pack(fill="x", padx=24, pady=(12, 0))
        for text, var in [("Majúscules (A-Z)", upper_var), ("Minúscules (a-z)", lower_var),
                            ("Dígits (0-9)", digit_var), ("Símbols (!@#...)", sym_var)]:
            tk.Checkbutton(cf, text=text, variable=var, font=("Segoe UI", 10), bg=COLORS["bg"],
                            fg=COLORS["text"], selectcolor=COLORS["bg_entry"],
                            activebackground=COLORS["bg"]).pack(anchor="w", pady=1)
        of = tk.Frame(dialog, bg=COLORS["bg"]); of.pack(fill="x", padx=24, pady=(16, 0))
        pwd_out = tk.Entry(of, font=("Consolas", 13), bg=COLORS["bg_entry"], fg=COLORS["success"],
                            insertbackground=COLORS["text"], relief="flat", bd=0,
                            readonlybackground=COLORS["bg_entry"])
        pwd_out.pack(fill="x", ipady=8)
        stf = tk.Frame(dialog, bg=COLORS["bg"]); stf.pack(fill="x", padx=24, pady=(4, 0))
        stc = tk.Canvas(stf, height=6, bg=COLORS["bg_entry"], highlightthickness=0); stc.pack(fill="x")
        stl = tk.Label(stf, text="", font=("Segoe UI", 9), fg=COLORS["text_dim"], bg=COLORS["bg"]); stl.pack(anchor="w")
        def do_gen():
            p = generate_password(len_var.get(), upper_var.get(), lower_var.get(), digit_var.get(), sym_var.get())
            pwd_out.config(state="normal"); pwd_out.delete(0, "end"); pwd_out.insert(0, p)
            score, text = password_strength(p); stc.delete("all")
            w = stc.winfo_width()
            if w < 10: w = 390
            fw = int(w * score / 100)
            color = COLORS["strength_weak"] if score < 40 else COLORS["strength_medium"] if score < 70 else COLORS["strength_strong"]
            stc.create_rectangle(0, 0, fw, 6, fill=color, outline=""); stl.config(text=text, fg=color)
        def do_copy():
            p = pwd_out.get()
            if p: self.root.clipboard_clear(); self.root.clipboard_append(p); messagebox.showinfo("Copiat", "Contrasenya copiada!", parent=dialog)
        bf = tk.Frame(dialog, bg=COLORS["bg"]); bf.pack(fill="x", padx=24, pady=(16, 0))
        self._make_button(bf, "🎲  Generar", do_gen, COLORS["accent"], width=12).pack(side="left", padx=(0, 8))
        self._make_button(bf, "📋  Copiar", do_copy, COLORS["bg_entry"], width=12).pack(side="left")
        do_gen()

    # ---- Tancar / Canviar Contrasenya ----
    def _on_close(self):
        if self.unsaved_changes and self.data:
            r = messagebox.askyesnocancel(
                "Canvis pendents",
                "Hi ha canvis sense desar.\nVols desar la base de dades abans de sortir?",
                parent=self.root)
            if r is None:
                return  # Cancel·lar: no tancar
            if r:
                self._save_db()
        if (self.ftp_config or self.gdrive_file_id) and self.db_path and os.path.exists(self.db_path):
            try: os.unlink(self.db_path)
            except: pass
        self.root.destroy()

    def _lock_db(self):
        if self.unsaved_changes:
            r = messagebox.askyesnocancel("Canvis pendents", "Vols desar abans de tancar?", parent=self.root)
            if r is None: return
            if r: self._save_db()
        if (self.ftp_config or self.gdrive_file_id) and self.db_path and os.path.exists(self.db_path):
            try: os.unlink(self.db_path)
            except: pass
        self.master_password = None; self.data = None; self.db_path = None
        self.ftp_config = None; self.gdrive_file_id = None; self.gdrive_filename = None
        self._show_welcome()

    def _change_master_password(self):
        old = self._ask_password("Contrasenya actual")
        if not old: return
        if old != self.master_password:
            messagebox.showerror("Error", "Contrasenya incorrecta.", parent=self.root); return
        new = self._ask_password("Nova contrasenya mestra", confirm=True)
        if not new: return
        self.master_password = new; self._save_db()
        messagebox.showinfo("Fet", "Contrasenya mestra canviada correctament.", parent=self.root)

    # ---- FTP ----

    def _ftp_connect(self, cfg):
        if cfg.get("use_tls"):
            ftp = ftplib.FTP_TLS()
            ftp.connect(cfg["host"], cfg["port"], timeout=10)
            ftp.login(cfg["user"], cfg["password"])
            ftp.prot_p()
        else:
            ftp = ftplib.FTP()
            ftp.connect(cfg["host"], cfg["port"], timeout=10)
            ftp.login(cfg["user"], cfg["password"])
        return ftp

    def _ftp_download(self, cfg, local_path):
        ftp = self._ftp_connect(cfg)
        try:
            with open(local_path, "wb") as f:
                ftp.retrbinary(f"RETR {cfg['path']}", f.write)
        finally:
            ftp.quit()

    def _ftp_upload(self, cfg, local_path):
        ftp = self._ftp_connect(cfg)
        try:
            with open(local_path, "rb") as f:
                ftp.storbinary(f"STOR {cfg['path']}", f)
        finally:
            ftp.quit()

    def _ftp_dialog(self):
        last = self.config.get("ftp_last", {})
        dialog = tk.Toplevel(self.root)
        dialog.title("Connexió FTP")
        dialog.configure(bg=COLORS["bg"])
        dialog.resizable(False, False)
        dialog.transient(self.root); dialog.grab_set()
        self._center_dialog(dialog, 420, 430)
        result = {"cfg": None}

        tk.Label(dialog, text="🌐  Connexió FTP", font=("Segoe UI", 13, "bold"),
                 fg=COLORS["accent_light"], bg=COLORS["bg"]).pack(pady=(18, 10))

        ff = tk.Frame(dialog, bg=COLORS["bg"]); ff.pack(fill="x", padx=30)
        entries = {}
        for label, key, default, secret in [
            ("Servidor:",       "host",     last.get("host", ""),         False),
            ("Port:",           "port",     str(last.get("port", 21)),    False),
            ("Usuari:",         "user",     last.get("user", ""),         False),
            ("Contrasenya FTP:","password", "",                           True),
            ("Ruta del fitxer:","path",     last.get("path", "/mydb.vkdb"), False),
        ]:
            tk.Label(ff, text=label, font=("Segoe UI", 9), fg=COLORS["text_dim"],
                     bg=COLORS["bg"], anchor="w").pack(fill="x", pady=(6, 0))
            e = tk.Entry(ff, show="●" if secret else "", font=("Segoe UI", 10),
                         bg=COLORS["bg_entry"], fg=COLORS["text"],
                         insertbackground=COLORS["text"], relief="flat", bd=0)
            e.pack(fill="x", ipady=5); e.insert(0, default)
            entries[key] = e

        tls_var = tk.BooleanVar(value=last.get("use_tls", False))
        tk.Checkbutton(ff, text="Connexió segura (FTPS)", variable=tls_var,
                       font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["text"],
                       selectcolor=COLORS["bg_entry"],
                       activebackground=COLORS["bg"]).pack(anchor="w", pady=(10, 0))

        def connect(event=None):
            host = entries["host"].get().strip()
            user = entries["user"].get().strip()
            path = entries["path"].get().strip()
            if not host or not user or not path:
                messagebox.showwarning("Avís", "Omple servidor, usuari i ruta.", parent=dialog); return
            try:
                port = int(entries["port"].get().strip())
            except ValueError:
                messagebox.showwarning("Avís", "El port ha de ser un número.", parent=dialog); return
            result["cfg"] = {"host": host, "port": port, "user": user,
                             "password": entries["password"].get(),
                             "path": path, "use_tls": tls_var.get()}
            dialog.destroy()

        entries["host"].focus_set()
        bf = tk.Frame(dialog, bg=COLORS["bg"]); bf.pack(pady=(14, 0))
        self._make_button(bf, "Connectar", connect, COLORS["accent"], width=12).pack(side="left", padx=(0, 8))
        self._make_button(bf, "Cancel·lar", dialog.destroy, COLORS["bg_entry"], width=12).pack(side="left")
        dialog.wait_window()
        return result["cfg"]

    def _open_ftp_db(self):
        cfg = self._ftp_dialog()
        if not cfg: return

        # Desa la configuració sense contrasenya
        self.config["ftp_last"] = {k: v for k, v in cfg.items() if k != "password"}
        save_config(self.config)

        # Descarrega a fitxer temporal
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".vkdb")
        os.close(tmp_fd)
        file_exists = True
        try:
            self._ftp_download(cfg, tmp_path)
        except ftplib.error_perm as e:
            if str(e).startswith("550"):
                file_exists = False  # Fitxer no trobat al servidor
            else:
                os.unlink(tmp_path)
                messagebox.showerror("Error FTP", f"No s'ha pogut accedir al fitxer:\n{e}", parent=self.root)
                return
        except Exception as e:
            os.unlink(tmp_path)
            messagebox.showerror("Error FTP", f"No s'ha pogut descarregar el fitxer:\n{e}", parent=self.root)
            return

        if not file_exists:
            if not messagebox.askyesno("Fitxer no trobat",
                    f"El fitxer «{cfg['path']}» no existeix al servidor.\n\n"
                    "Vols crear una nova base de dades en aquesta ubicació?",
                    parent=self.root):
                os.unlink(tmp_path); return
            pwd = self._ask_password("Crea la contrasenya mestra", confirm=True)
            if not pwd:
                os.unlink(tmp_path); return
            data = _new_db_data()
            blob = encrypt_db(data, pwd)
            with open(tmp_path, "wb") as f: f.write(blob)
            try:
                self._ftp_upload(cfg, tmp_path)
            except Exception as e:
                os.unlink(tmp_path)
                messagebox.showerror("Error FTP", f"No s'ha pogut crear el fitxer al servidor:\n{e}", parent=self.root)
                return
        else:
            # Obre amb la contrasenya mestra
            pwd = self._ask_password("Introdueix la contrasenya mestra")
            if not pwd:
                os.unlink(tmp_path); return
            try:
                with open(tmp_path, "rb") as f: blob = f.read()
                data = decrypt_db(blob, pwd)
                if "root" not in data: data = _migrate_v2_to_v3(data)
            except ValueError as e:
                os.unlink(tmp_path)
                messagebox.showerror("Error", str(e), parent=self.root); return
            except Exception as e:
                os.unlink(tmp_path)
                messagebox.showerror("Error", f"No s'ha pogut obrir: {e}", parent=self.root); return

        self.data = data
        self.db_path = tmp_path
        self.master_password = pwd
        self.ftp_config = cfg
        root_node = self.data["root"]
        self.current_group_id = (root_node["children"][0]["id"]
                                 if root_node.get("children") else root_node["id"])
        self._show_main()

    # ---- Google Drive ----

    def _gdrive_token(self):
        """Retorna un access token vàlid, refrescant-lo si ha caducat."""
        creds = self.config.get("gdrive_credentials", {})
        if not creds.get("refresh_token"):
            return None
        if time.time() < creds.get("token_expiry", 0) - 60 and creds.get("access_token"):
            return creds["access_token"]
        data = urllib.parse.urlencode({
            "client_id":     creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": creds["refresh_token"],
            "grant_type":    "refresh_token",
        }).encode()
        try:
            req = urllib.request.Request("https://oauth2.googleapis.com/token",
                                         data=data, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                tokens = json.loads(resp.read())
            creds["access_token"]  = tokens["access_token"]
            creds["token_expiry"]  = time.time() + tokens.get("expires_in", 3600)
            self.config["gdrive_credentials"] = creds
            save_config(self.config)
            return creds["access_token"]
        except Exception:
            return None

    def _gdrive_authorize(self, client_id, client_secret):
        """OAuth 2.0 PKCE: obre el navegador, espera el callback i retorna els tokens."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("localhost", 0))
            port = s.getsockname()[1]

        verifier  = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        redirect_uri = f"http://localhost:{port}"

        params = urllib.parse.urlencode({
            "client_id":             client_id,
            "redirect_uri":          redirect_uri,
            "response_type":         "code",
            "scope":                 "https://www.googleapis.com/auth/drive.file",
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
            "access_type":           "offline",
            "prompt":                "consent",
        })
        auth_url = f"https://accounts.google.com/o/oauth2/auth?{params}"

        holder = {"code": None, "done": threading.Event()}

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self_h):
                p = urllib.parse.parse_qs(urllib.parse.urlparse(self_h.path).query)
                if "code" in p:
                    holder["code"] = p["code"][0]
                self_h.send_response(200)
                self_h.send_header("Content-type", "text/html; charset=utf-8")
                self_h.end_headers()
                self_h.wfile.write(
                    b"<html><body style='font-family:sans-serif;text-align:center;padding:40px'>"
                    b"<h2>&#x2705; Autoritzat correctament!</h2>"
                    b"<p>Pots tancar aquesta finestra i tornar a qmrClau.</p>"
                    b"</body></html>")
                holder["done"].set()
            def log_message(self_h, *_): pass

        srv = http.server.HTTPServer(("localhost", port), _Handler)
        t = threading.Thread(target=srv.serve_forever); t.daemon = True; t.start()
        webbrowser.open(auth_url)

        # Diàleg d'espera (no bloqueja la UI)
        wd = tk.Toplevel(self.root)
        wd.title("Autoritzant amb Google")
        wd.configure(bg=COLORS["bg"]); wd.resizable(False, False)
        wd.transient(self.root); wd.grab_set()
        self._center_dialog(wd, 400, 160)
        tk.Label(wd, text="🌐  Esperant autorització...", font=("Segoe UI", 12, "bold"),
                 fg=COLORS["accent_light"], bg=COLORS["bg"]).pack(pady=(30, 8))
        tk.Label(wd, text="S'ha obert el navegador. Autoritza l'accés i torna aquí.",
                 font=("Segoe UI", 9), fg=COLORS["text_dim"], bg=COLORS["bg"]).pack()

        def _poll():
            if holder["done"].is_set():
                try: srv.shutdown()
                except: pass
                wd.destroy()
            elif wd.winfo_exists():
                wd.after(300, _poll)

        wd.after(300, _poll)
        wd.wait_window()

        if not holder["code"]:
            try: srv.shutdown()
            except: pass
            return None

        data = urllib.parse.urlencode({
            "client_id":     client_id,
            "client_secret": client_secret,
            "code":          holder["code"],
            "code_verifier": verifier,
            "grant_type":    "authorization_code",
            "redirect_uri":  redirect_uri,
        }).encode()
        req = urllib.request.Request("https://oauth2.googleapis.com/token",
                                     data=data, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())

    def _gdrive_request(self, method, url, token, data=None, content_type=None):
        headers = {"Authorization": f"Bearer {token}"}
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            return json.loads(body) if body else {}

    def _gdrive_find_file(self, token, filename):
        fn = filename.replace("'", "\\'")
        q  = urllib.parse.quote(f"name='{fn}' and trashed=false")
        result = self._gdrive_request("GET",
            f"https://www.googleapis.com/drive/v3/files?q={q}&fields=files(id,name)", token)
        files = result.get("files", [])
        return files[0]["id"] if files else None

    def _gdrive_download(self, token, file_id, local_path):
        req = urllib.request.Request(
            f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            with open(local_path, "wb") as f:
                f.write(resp.read())

    def _gdrive_upload_new(self, token, filename, local_path):
        with open(local_path, "rb") as f:
            content = f.read()
        boundary = "qmrclau_" + secrets.token_hex(8)
        metadata = json.dumps({"name": filename}).encode()
        body = (
            f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            .encode() + metadata +
            f"\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
            .encode() + content +
            f"\r\n--{boundary}--".encode()
        )
        result = self._gdrive_request("POST",
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id",
            token, data=body,
            content_type=f"multipart/related; boundary={boundary}")
        return result["id"]

    def _gdrive_upload_update(self, token, file_id, local_path):
        with open(local_path, "rb") as f:
            content = f.read()
        self._gdrive_request("PATCH",
            f"https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=media",
            token, data=content, content_type="application/octet-stream")

    def _gdrive_dialog(self):
        creds     = self.config.get("gdrive_credentials", {})
        last_file = self.config.get("gdrive_last_filename", "mydb.vkdb")
        dialog = tk.Toplevel(self.root)
        dialog.title("Google Drive")
        dialog.configure(bg=COLORS["bg"]); dialog.resizable(False, False)
        dialog.transient(self.root); dialog.grab_set()
        self._center_dialog(dialog, 440, 310)
        result = {"cfg": None}

        tk.Label(dialog, text="☁️  Google Drive", font=("Segoe UI", 13, "bold"),
                 fg=COLORS["accent_light"], bg=COLORS["bg"]).pack(pady=(18, 2))
        tk.Label(dialog,
                 text="Credencials OAuth 2.0 (tipus Aplicació d'escriptori)\nconsole.cloud.google.com",
                 font=("Segoe UI", 8), fg=COLORS["text_dim"], bg=COLORS["bg"],
                 justify="center").pack()

        ff = tk.Frame(dialog, bg=COLORS["bg"]); ff.pack(fill="x", padx=30, pady=(10, 0))
        entries = {}
        for label, key, default, secret in [
            ("Client ID:",            "client_id",     creds.get("client_id", ""),     False),
            ("Client Secret:",        "client_secret", creds.get("client_secret", ""), True),
            ("Nom del fitxer a Drive:","filename",      last_file,                      False),
        ]:
            tk.Label(ff, text=label, font=("Segoe UI", 9), fg=COLORS["text_dim"],
                     bg=COLORS["bg"], anchor="w").pack(fill="x", pady=(8, 0))
            e = tk.Entry(ff, show="●" if secret else "", font=("Segoe UI", 10),
                         bg=COLORS["bg_entry"], fg=COLORS["text"],
                         insertbackground=COLORS["text"], relief="flat", bd=0)
            e.pack(fill="x", ipady=5); e.insert(0, default)
            entries[key] = e

        def connect(event=None):
            cid  = entries["client_id"].get().strip()
            csec = entries["client_secret"].get().strip()
            fn   = entries["filename"].get().strip()
            if not cid or not csec or not fn:
                messagebox.showwarning("Avís", "Omple tots els camps.", parent=dialog); return
            result["cfg"] = {"client_id": cid, "client_secret": csec, "filename": fn}
            dialog.destroy()

        entries["client_id"].focus_set()
        bf = tk.Frame(dialog, bg=COLORS["bg"]); bf.pack(pady=(14, 0))
        self._make_button(bf, "Connectar", connect, COLORS["accent"], width=12).pack(side="left", padx=(0, 8))
        self._make_button(bf, "Cancel·lar", dialog.destroy, COLORS["bg_entry"], width=12).pack(side="left")
        dialog.wait_window()
        return result["cfg"]

    def _open_gdrive_db(self):
        cfg = self._gdrive_dialog()
        if not cfg: return

        client_id, client_secret, filename = cfg["client_id"], cfg["client_secret"], cfg["filename"]
        self.config["gdrive_last_filename"] = filename

        # Autoritza si cal (credencials noves o canviades)
        creds = self.config.get("gdrive_credentials", {})
        need_auth = (not creds.get("refresh_token") or
                     creds.get("client_id") != client_id or
                     creds.get("client_secret") != client_secret)
        if need_auth:
            try:
                tokens = self._gdrive_authorize(client_id, client_secret)
            except Exception as e:
                messagebox.showerror("Error Drive", f"Error d'autorització:\n{e}", parent=self.root); return
            if not tokens:
                messagebox.showwarning("Cancel·lat", "Autorització cancel·lada.", parent=self.root); return
            self.config["gdrive_credentials"] = {
                "client_id":     client_id,
                "client_secret": client_secret,
                "access_token":  tokens["access_token"],
                "refresh_token": tokens.get("refresh_token", creds.get("refresh_token", "")),
                "token_expiry":  time.time() + tokens.get("expires_in", 3600),
            }
            save_config(self.config)

        token = self._gdrive_token()
        if not token:
            messagebox.showerror("Error", "No s'ha pogut obtenir el token d'accés.", parent=self.root); return

        try:
            file_id = self._gdrive_find_file(token, filename)
        except Exception as e:
            messagebox.showerror("Error Drive", f"Error cercant el fitxer:\n{e}", parent=self.root); return

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".vkdb")
        os.close(tmp_fd)
        create_new = False

        if file_id:
            try:
                self._gdrive_download(token, file_id, tmp_path)
            except Exception as e:
                os.unlink(tmp_path)
                messagebox.showerror("Error Drive", f"No s'ha pogut descarregar:\n{e}", parent=self.root); return
        else:
            if not messagebox.askyesno("Fitxer no trobat",
                    f"El fitxer «{filename}» no existeix a Drive.\n\n"
                    "Vols crear una nova base de dades?", parent=self.root):
                os.unlink(tmp_path); return
            create_new = True

        pwd = self._ask_password("Crea la contrasenya mestra" if create_new
                                 else "Introdueix la contrasenya mestra",
                                 confirm=create_new)
        if not pwd:
            os.unlink(tmp_path); return

        if create_new:
            data = _new_db_data()
            blob = encrypt_db(data, pwd)
            with open(tmp_path, "wb") as f: f.write(blob)
            try:
                file_id = self._gdrive_upload_new(token, filename, tmp_path)
            except Exception as e:
                os.unlink(tmp_path)
                messagebox.showerror("Error Drive", f"No s'ha pogut crear el fitxer:\n{e}", parent=self.root); return
        else:
            try:
                with open(tmp_path, "rb") as f: blob = f.read()
                data = decrypt_db(blob, pwd)
                if "root" not in data: data = _migrate_v2_to_v3(data)
            except ValueError as e:
                os.unlink(tmp_path); messagebox.showerror("Error", str(e), parent=self.root); return
            except Exception as e:
                os.unlink(tmp_path)
                messagebox.showerror("Error", f"No s'ha pogut obrir: {e}", parent=self.root); return

        self.data = data; self.db_path = tmp_path; self.master_password = pwd
        self.gdrive_file_id = file_id; self.gdrive_filename = filename; self.ftp_config = None
        root_node = self.data["root"]
        self.current_group_id = (root_node["children"][0]["id"]
                                 if root_node.get("children") else root_node["id"])
        self._show_main()

    # ---- Exportar / Importar CSV ----

    def _collect_entries_for_export(self, group, parent_path, rows):
        path = f"{parent_path}/{group['name']}" if parent_path else group["name"]
        for entry in group.get("entries", []):
            rows.append([
                path,
                entry.get("title", ""),
                entry.get("username", ""),
                entry.get("password", ""),
                entry.get("url", ""),
                entry.get("notes", ""),
            ])
        for child in group.get("children", []):
            self._collect_entries_for_export(child, path, rows)

    def _export_csv(self):
        if not self.data:
            return
        pwd = self._ask_password("Confirma la contrasenya mestra")
        if not pwd or pwd != self.master_password:
            messagebox.showerror("Error", "Contrasenya incorrecta.", parent=self.root)
            return
        if not messagebox.askyesno("Advertència de seguretat",
                "El fitxer CSV es desarà sense xifrar.\n"
                "Les contrasenyes seran visibles en text pla.\n\n"
                "Vols continuar?", parent=self.root):
            return
        path = filedialog.asksaveasfilename(title="Exportar a CSV",
            defaultextension=".csv", filetypes=[("CSV", "*.csv"), ("Tots", "*.*")])
        if not path:
            return
        rows = []
        self._collect_entries_for_export(self.data["root"], "", rows)
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["Grup", "Títol", "Usuari", "Contrasenya", "URL", "Notes"])
                writer.writerows(rows)
            messagebox.showinfo("Exportació completada",
                f"S'han exportat {len(rows)} entrades a:\n{path}", parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", f"No s'ha pogut exportar:\n{e}", parent=self.root)

    def _find_or_create_group_path(self, path_str):
        if not path_str:
            ch = self.data["root"].get("children", [])
            return ch[0] if ch else self.data["root"]
        parts = [p.strip() for p in path_str.replace("\\", "/").split("/") if p.strip()]
        if parts and parts[0].lower() in ("arrel", "root"):
            parts = parts[1:]
        if not parts:
            ch = self.data["root"].get("children", [])
            return ch[0] if ch else self.data["root"]
        current = self.data["root"]
        for part in parts:
            found = next((c for c in current.get("children", [])
                          if c["name"].lower() == part.lower()), None)
            if found:
                current = found
            else:
                new_group = _make_group(part)
                current.setdefault("children", []).append(new_group)
                current = new_group
        return current

    def _import_csv(self):
        if not self.data:
            return
        pwd = self._ask_password("Confirma la contrasenya mestra")
        if not pwd or pwd != self.master_password:
            messagebox.showerror("Error", "Contrasenya incorrecta.", parent=self.root)
            return
        path = filedialog.askopenfilename(title="Importar des de CSV",
            filetypes=[("CSV", "*.csv"), ("Tots", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                rows = list(csv.DictReader(f))
        except Exception as e:
            messagebox.showerror("Error", f"No s'ha pogut llegir el fitxer:\n{e}", parent=self.root)
            return
        if not rows:
            messagebox.showwarning("Avís", "El fitxer CSV és buit o no té capçalera.", parent=self.root)
            return
        # Detecta les columnes per nom (suporta català i anglès)
        col = {}
        for key in rows[0].keys():
            k = key.lower().strip()
            if k in ("grup", "group", "folder", "carpeta"):         col["group"]    = key
            elif k in ("títol", "titol", "title", "name", "nom"):   col["title"]    = key
            elif k in ("usuari", "username", "user", "login"):       col["username"] = key
            elif k in ("contrasenya", "password", "pass"):           col["password"] = key
            elif k in ("url", "website", "web"):                     col["url"]      = key
            elif k in ("notes", "nota", "note", "comentari"):        col["notes"]    = key
        if "title" not in col:
            messagebox.showerror("Error",
                "No s'ha trobat la columna de títol al CSV.\n"
                "La capçalera ha de contenir: Títol, Title o Name.", parent=self.root)
            return
        now = datetime.now().isoformat()
        imported = skipped = 0
        for row in rows:
            title = row.get(col["title"], "").strip()
            if not title:
                skipped += 1
                continue
            group = self._find_or_create_group_path(row.get(col.get("group", ""), ""))
            group["entries"].append({
                "title":    title,
                "username": row.get(col.get("username", ""), "").strip(),
                "password": row.get(col.get("password", ""), ""),
                "url":      row.get(col.get("url", ""), "").strip(),
                "notes":    row.get(col.get("notes", ""), "").strip(),
                "created":  now, "modified": now,
            })
            imported += 1
        if imported == 0:
            messagebox.showwarning("Res importat", "No s'ha trobat cap entrada vàlida al fitxer.", parent=self.root)
            return
        self.unsaved_changes = True
        self._refresh_tree(); self._refresh_entries(); self._update_title()
        msg = f"S'han importat {imported} entrades."
        if skipped:
            msg += f"\n({skipped} files ignorades per manca de títol)"
        messagebox.showinfo("Importació completada", msg, parent=self.root)


def _create_key_icon():
    """Crea una icona de clau 32x32 amb PhotoImage (sense fitxers externs)."""
    # Disseny de la clau en una graella 16x16 (s'escala a 32x32)
    # K = clau, cada píxel es duplica a 2x2 per al format 32x32
    K = COLORS["accent"]
    pixels = [
        # Arc superior de l'anell
        (2,1),(3,1),(4,1),(5,1),
        # Costats de l'anell
        (1,2),(6,2),
        (1,3),(6,3),
        # Fila central: costat esquerre de l'anell + eix horitzontal
        (1,4),(6,4),(7,4),(8,4),(9,4),(10,4),(11,4),(12,4),(13,4),(14,4),
        # Fila amb dents: costat esquerre anell + dents a cols 10 i 13
        (1,5),(6,5),(10,5),(13,5),
        # Arc inferior de l'anell
        (2,6),(3,6),(4,6),(5,6),
    ]
    img = tk.PhotoImage(width=32, height=32)
    for x, y in pixels:
        for dx, dy in [(0,0),(1,0),(0,1),(1,1)]:
            img.put(K, to=(x*2+dx, y*2+dy))
    return img


def main():
    root = tk.Tk()
    try:
        icon = _create_key_icon()
        root.iconphoto(True, icon)
    except Exception:
        pass
    try: root.iconname("qmrClau")
    except: pass
    app = QmrClauApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()