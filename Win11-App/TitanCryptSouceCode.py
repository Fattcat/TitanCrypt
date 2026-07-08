import io
import re
import time
import threading
import os
import shutil
import webbrowser
import sys
import socket
import secrets
import json
from datetime import datetime
from pathlib import Path
from PIL import Image
from collections import defaultdict
import base64

# Moderná kryptografia (nahrádza pôvodné XOR "šifrovanie")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
from markupsafe import escape

# Tkinter import (iba ak bežíme ako GUI appka)
USE_GUI = "--no-gui" not in sys.argv
if USE_GUI:
    import tkinter as tk
    from tkinter import messagebox, font, ttk

# Flask + Werkzeug (shutdown hook)
from flask import Flask, request, render_template_string, send_file, jsonify
try:
    from werkzeug import run_simple
    from werkzeug.serving import make_server
except ImportError:
    # Fallback pre staršie verzie
    pass

# === NASTAVENIA ===
HISTORY_ROOT = Path("C:/TitanCrypt")
HOST = "127.0.0.1"
DEFAULT_PORT = 5000
MAX_PORT_ATTEMPTS = 10

app = Flask(__name__)
app.static_folder = str(HISTORY_ROOT / "static")
# Náhodný secret_key generovaný pri každom štarte (pôvodne bol natvrdo v kóde = falšovanie session/cookie)
app.secret_key = secrets.token_hex(32)
# Obmedzenie veľkosti uploadu (25 MB) - ochrana proti DoS / veľkým súborom
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

# Maximálny počet pixelov, ktoré ešte otvoríme cez PIL (ochrana proti "image bomb")
PIL_MAX_PIXELS = 40_000_000  # cca 40 MPx

# Globálne premenné pre výsledky a server
_encrypted_image_bytes = None
_decryption_key_bytes = None
_decrypted_image_buffer = None
_decrypted_filename = None
_encrypted_text = None
_original_text_length = 0
_encrypted_text_length = 0
_decrypted_text = None
task_status = defaultdict(lambda: {"progress": 0, "eta": 0, "done": False, "error": None, "result": None, "cancelled": False})

# Server kontrola
server_instance = None
server_thread = None
stop_event = threading.Event()


# === UTILS ===
def is_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, port))
            return True
        except OSError:
            return False

def find_free_port(start_port=DEFAULT_PORT, max_attempts=MAX_PORT_ATTEMPTS):
    for offset in range(max_attempts):
        port = start_port + offset
        if is_port_free(port):
            return port
    raise RuntimeError(f"Žiadny voľný port medzi {start_port}–{start_port + max_attempts - 1}")


# === HISTORY ===
def ensure_history_dirs():
    try:
        (HISTORY_ROOT / "TextCrypt").mkdir(parents=True, exist_ok=True)
        (HISTORY_ROOT / "ImgCrypt").mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[HIST] Chyba: {e}")



import urllib.request
import ssl

def ensure_static_assets():
    """
    Zabezpečí, že v C:/TitanCrypt/static/ existujú všetky potrebné súbory:
    - TitanCryptLogo2.ico
    - TitanCryptLogo2.png
    - download.png
    Ak niektorý chýba → stiahne ho z GitHubu (raw link).
    """
    static_dir = HISTORY_ROOT / "static"
    static_dir.mkdir(parents=True, exist_ok=True)

    # Zoznam súborov: (názov, github_raw_url)
    assets = [
        ("TitanCryptLogo2.ico", "https://github.com/Fattcat/TitanCrypt/raw/main/Win11-App/static/TitanCryptLogo2.ico"),
        ("TitanCryptLogo2.png", "https://github.com/Fattcat/TitanCrypt/raw/main/Win11-App/static/TitanCryptLogo2.png"),
        ("download.png", "https://github.com/Fattcat/TitanCrypt/raw/main/Win11-App/static/download.png"),
    ]

    for filename, url in assets:
        path = static_dir / filename
        if not path.exists():
            try:
                print(f"[ASSETS] Sťahujem {filename} z GitHubu...")
                # POZOR: overenie SSL certifikátu MUSÍ zostať zapnuté (predtým bolo vypnuté -> MITM riziko)
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(url, context=ctx, timeout=10) as response:
                    path.write_bytes(response.read())
                print(f"[ASSETS] ✅ {filename} uložený.")
            except Exception as e:
                print(f"[ASSETS] ❌ Chyba pri sťahovaní {filename}: {e}")
                # Fallback: vytvor minimálny placeholder (pre download.png)
                if filename == "download.png":
                    # Vytvor jednoduchú šípku ako PNG placeholder
                    try:
                        from PIL import Image, ImageDraw
                        img = Image.new("RGBA", (18, 18), (0, 0, 0, 0))
                        draw = ImageDraw.Draw(img)
                        # Jednoduchý smerový trojuholník ↓
                        draw.polygon([(4, 6), (14, 6), (9, 12)], fill=(255, 255, 255))
                        img.save(path)
                        print(f"[ASSETS] ✅ Vytvorený fallback download.png")
                    except:
                        pass

def save_text_history(original_text: str, key: str, encrypted_text: str):
    try:
        ensure_history_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = HISTORY_ROOT / "TextCrypt" / f"Encrypted_{timestamp}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "key.txt").write_text(key, encoding="utf-8")
        (folder / "EncryptedText.txt").write_text(encrypted_text, encoding="utf-8")
        (folder / "OriginalText.txt").write_text(original_text, encoding="utf-8")
    except Exception as e:
        print(f"[HIST] Text chyba: {e}")

def save_image_history(original_image_bytes: bytes, original_filename: str, key: str, encrypted_image_bytes: bytes, decryption_key_bytes: bytes):
    try:
        ensure_history_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = HISTORY_ROOT / "ImgCrypt" / f"Encrypted_{timestamp}"
        folder.mkdir(parents=True, exist_ok=True)
        safe_name = Path(original_filename).name or "original.png"
        (folder / safe_name).write_bytes(original_image_bytes)
        (folder / "key.txt").write_text(key, encoding="utf-8")
        (folder / "decryption_key.key").write_bytes(decryption_key_bytes)
        (folder / "encrypted_image.png").write_bytes(encrypted_image_bytes)
    except Exception as e:
        print(f"[HIST] Img chyba: {e}")


# === CORE LOGIC ===
def normalize_key_for_storage(raw: str) -> str:
    if raw is None: return ""
    s = re.sub(r'[^A-Za-z0-9]', '', raw).upper()
    return s[:25]


# === MODERNÁ KRYPTOGRAFIA (AES-256-GCM + scrypt KDF) ===
# Pôvodná implementácia používala XOR (reverzibilné len opakovaním kľúča -> triviálne
# prelomiteľné pri known-plaintext útoku) a pri obrázkoch dokonca iba PREHADZOVALA
# pixely (Mersenne-Twister PRNG, predvídateľný seed) bez toho, aby menila ich hodnoty -
# obsah obrázka bol štatisticky rekonštruovateľný z histogramu farieb.
#
# Nové riešenie:
#   - Kľúč odvodený cez scrypt (pomalá KDF, odolná voči brute-force/GPU útokom)
#     z náhodnej "salt" (uloženej pri šifrovaní).
#   - Samotné dáta šifrované AES-256-GCM (autentifikované šifrovanie):
#       * zaisťuje dôvernosť AJ integritu (detekuje akúkoľvek zmenu ciphertextu)
#       * náhodný nonce pre každé šifrovanie (nikdy sa neopakuje)
#
# SCRYPT_N/R/P sú zámerne nižšie ako "odporúčané produkčné" hodnoty, pretože ide
# o lokálnu desktopovú appku bez online brute-force vektora (server počúva len na
# 127.0.0.1) - dá sa kedykoľvek sprísniť zvýšením SCRYPT_N.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LEN = 16
NONCE_LEN = 12
AES_KEY_LEN = 32  # AES-256


def derive_key(password: str, salt: bytes, length: int = AES_KEY_LEN) -> bytes:
    """Odvodí kryptografický kľúč z používateľského hesla pomocou scrypt."""
    kdf = Scrypt(salt=salt, length=length, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encode_image_to_files(file_bytes: bytes, key: str) -> (bytes, bytes):
    """
    Zašifruje pôvodné bajty súboru obrázka pomocou AES-256-GCM.
    Vracia (encrypted_image_bytes, key_file_bytes):
      - encrypted_image_bytes = nonce (12B) + ciphertext (vrátane GCM tagu)
      - key_file_bytes        = salt (16B) použitá pre scrypt
    Bez správneho hesla NIE JE možné zo salt/nonce/ciphertextu nič odvodiť.
    """
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    aes_key = derive_key(key, salt)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    encrypted_image_bytes = nonce + ciphertext
    key_file_bytes = salt
    return encrypted_image_bytes, key_file_bytes


def decode_files_to_image(encrypted_image_bytes: bytes, key_file_bytes: bytes, user_key: str):
    """
    Dešifruje AES-256-GCM ciphertext späť na pôvodné bajty obrázka.
    Nesprávny kľúč / poškodený súbor -> InvalidTag (autentifikácia zlyhá), nie tiché
    poškodenie dát ako pri pôvodnom XOR variante.
    """
    if len(key_file_bytes) != SALT_LEN:
        raise ValueError("Neplatný súbor s kľúčom (zlá dĺžka salt)")
    if len(encrypted_image_bytes) < NONCE_LEN:
        raise ValueError("Neplatný zašifrovaný súbor")

    salt = key_file_bytes
    nonce = encrypted_image_bytes[:NONCE_LEN]
    ciphertext = encrypted_image_bytes[NONCE_LEN:]
    aes_key = derive_key(user_key, salt)
    aesgcm = AESGCM(aes_key)
    try:
        original_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Nesprávny kľúč alebo poškodený/pozmenený súbor")

    if len(original_bytes) > PIL_MAX_PIXELS:  # hrubá ochrana pred extrémne veľkými dátami
        raise ValueError("Dešifrovaný obsah je neprimerane veľký")

    original_img = Image.open(io.BytesIO(original_bytes))
    original_img.load()
    width, height = original_img.size
    return original_img, width, height


def text_encrypt(plain_text: str, key: str) -> str:
    """AES-256-GCM šifrovanie textu. Výstup: hex(salt) + hex(nonce) + hex(ciphertext+tag)."""
    if not plain_text or not key:
        return ""
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    aes_key = derive_key(key, salt)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)
    return (salt + nonce + ciphertext).hex()


def text_decrypt(encrypted_text: str, key: str) -> str:
    """Opačný krok k text_encrypt. GCM tag zaručí, že pri zlom kľúči/pozmenenom
    texte dostaneme jasnú chybu namiesto ticho poškodeného výstupu."""
    if not encrypted_text or not key:
        return ""
    try:
        if not re.match(r'^[0-9a-fA-F]+$', encrypted_text):
            raise ValueError("Neplatný hex reťazec")
        raw = bytes.fromhex(encrypted_text)
        min_len = SALT_LEN + NONCE_LEN
        if len(raw) <= min_len:
            raise ValueError("Zašifrovaný text je príliš krátky / neplatný")
        salt = raw[:SALT_LEN]
        nonce = raw[SALT_LEN:min_len]
        ciphertext = raw[min_len:]
        aes_key = derive_key(key, salt)
        aesgcm = AESGCM(aes_key)
        try:
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise ValueError("Nesprávny kľúč alebo pozmenený text")
        return decrypted_bytes.decode("utf-8")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Dešifrovanie zlyhalo: {e}")

def get_step_delay(mode):
    delays = {"high": 0.005, "medium": 0.015, "slow": 0.04, "veryslow": 0.1}
    return delays.get(mode, 0.015)

def simulate_progress_with_mode(task_id, total_steps=100, mode="medium"):
    delay = get_step_delay(mode)
    for i in range(1, total_steps + 1):
        if task_status[task_id].get("cancelled") or stop_event.is_set():
            return False
        task_status[task_id]["progress"] = i
        remaining = total_steps - i
        task_status[task_id]["eta"] = round(remaining * delay, 1)
        time.sleep(delay)
    return True

def encrypt_task(task_id, file_bytes, key_raw, mode="medium", original_filename="unknown.png"):
    try:
        key_clean = normalize_key_for_storage(key_raw)
        if len(key_clean) != 25:
            task_status[task_id]["error"] = "Kľúč: presne 25 znakov (A–Z, 0–9)"
            return
        # Over, že ide skutočne o obrázok, a ochráň sa pred "image bomb" (extrémne rozmery)
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()
        img = Image.open(io.BytesIO(file_bytes))
        if img.size[0] * img.size[1] > PIL_MAX_PIXELS:
            task_status[task_id]["error"] = "Obrázok je príliš veľký"
            return
        if not simulate_progress_with_mode(task_id, total_steps=80, mode=mode):
            task_status[task_id]["error"] = "Zrušené"
            return
        encrypted_img_bytes, decryption_key_bytes = encode_image_to_files(file_bytes, key_clean)
        global _encrypted_image_bytes, _decryption_key_bytes
        _encrypted_image_bytes = encrypted_img_bytes
        _decryption_key_bytes = decryption_key_bytes
        save_image_history(file_bytes, original_filename, key_clean, encrypted_img_bytes, decryption_key_bytes)
        task_status[task_id]["done"] = True
        task_status[task_id]["result"] = "encrypt_success"
    except Exception as e:
        task_status[task_id]["error"] = f"Chyba: {str(e)}"

def decrypt_task(task_id, image_bytes, key_bytes, user_key, mode="medium"):
    try:
        key_clean = normalize_key_for_storage(user_key)
        if len(key_clean) != 25:
            task_status[task_id]["error"] = "Kľúč: presne 25 znakov (A–Z, 0–9)"
            return
        if not simulate_progress_with_mode(task_id, total_steps=80, mode=mode):
            task_status[task_id]["error"] = "Zrušené"
            return
        img, w, h = decode_files_to_image(image_bytes, key_bytes, key_clean)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        global _decrypted_image_buffer, _decrypted_filename
        _decrypted_image_buffer = buf.getvalue()
        _decrypted_filename = f"img{w}x{h}.png"
        task_status[task_id]["done"] = True
        task_status[task_id]["result"] = "decrypt_success"
    except Exception as e:
        task_status[task_id]["error"] = f"Chyba: {str(e)}"


# === CSRF / DRIVE-BY OCHRANA ===
# Server počúva len na 127.0.0.1, ale to NEBRÁNI škodlivej stránke otvorenej v tom
# istom prehliadači poslať fetch/POST na http://127.0.0.1:PORT/... (tzv. localhost
# CSRF / drive-by útok). Pôvodný kód takéto požiadavky vôbec nefiltroval, takže
# /shutdown aj /history/delete/... šlo spustiť z ľubovoľnej webstránky.
STATE_CHANGING_PATHS = {
    "/start_encrypt", "/start_decrypt", "/text_encrypt", "/text_decrypt",
    "/shutdown",
}

@app.before_request
def _csrf_origin_guard():
    if request.method != "POST":
        return None
    if not (request.path in STATE_CHANGING_PATHS or request.path.startswith("/history/delete/")
            or request.path.startswith("/cancel_task/")):
        return None
    origin = request.headers.get("Origin") or request.headers.get("Referer") or ""
    allowed_prefixes = (f"http://{HOST}:", f"https://{HOST}:")
    if origin and not origin.startswith(allowed_prefixes):
        return jsonify({"error": "Zakázaný pôvod požiadavky (CSRF ochrana)"}), 403
    return None


# === FLASK ROUTES ===
@app.route("/", methods=["GET"])
def index():
    task = request.args.get('task')
    context = {}
    if task == "encrypt_success": context["enc_success"] = True
    elif task == "decrypt_success": 
        context["show_decrypted_image"] = True
        context["filename"] = _decrypted_filename or "img.png"
    return render_template_string(INDEX_HTML, **context)

@app.route("/start_encrypt", methods=["POST"])
def start_encrypt():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "Nebol vybraný obrázok"}), 400
        file = request.files['image']
        key_raw = request.form.get('key', '')
        mode = request.form.get('speed_mode', 'medium')
        file_bytes = file.read()
        if not file_bytes:
            return jsonify({"error": "Súbor je prázdny"}), 400
        task_id = str(time.time()).replace(".", "")
        threading.Thread(
            target=encrypt_task,
            args=(task_id, file_bytes, key_raw, mode, file.filename),
            daemon=True
        ).start()
        return jsonify({"task_id": task_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/start_decrypt", methods=["POST"])
def start_decrypt():
    try:
        if 'image_file' not in request.files or 'key_file' not in request.files:
            return jsonify({"error": "Chýbajú súbory"}), 400
        image_file = request.files['image_file']
        key_file = request.files['key_file']
        user_key = request.form.get('key', '')
        mode = request.form.get('speed_mode', 'medium')
        image_bytes = image_file.read()
        key_bytes = key_file.read()
        if not image_bytes or not key_bytes:
            return jsonify({"error": "Jeden zo súborov je prázdny"}), 400
        task_id = str(time.time()).replace(".", "")
        threading.Thread(target=decrypt_task, args=(task_id, image_bytes, key_bytes, user_key, mode), daemon=True).start()
        return jsonify({"task_id": task_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cancel_task/<task_id>", methods=["POST"])
def cancel_task(task_id):
    task_status[task_id]["cancelled"] = True
    return jsonify({"status": "cancelled"})

@app.route("/status/<task_id>")
def task_status_route(task_id):
    return jsonify(task_status[task_id])

@app.route("/download_encrypted_image")
def download_encrypted_image():
    global _encrypted_image_bytes
    if _encrypted_image_bytes is None: return "Žiadny súbor", 404
    return send_file(io.BytesIO(_encrypted_image_bytes), mimetype='image/png', as_attachment=True, download_name='encrypted_image.png')

@app.route("/download_decryption_key")
def download_decryption_key():
    global _decryption_key_bytes
    if _decryption_key_bytes is None: return "Žiadny súbor", 404
    return send_file(io.BytesIO(_decryption_key_bytes), mimetype='application/octet-stream', as_attachment=True, download_name='decryption_key.key')

@app.route("/preview_decrypted")
def preview_decrypted():
    global _decrypted_image_buffer
    if _decrypted_image_buffer is None: return "No image", 404
    return send_file(io.BytesIO(_decrypted_image_buffer), mimetype='image/png')

@app.route("/download_decrypted")
def download_decrypted():
    global _decrypted_image_buffer, _decrypted_filename
    if _decrypted_image_buffer is None: return "Žiadny súbor", 404
    return send_file(io.BytesIO(_decrypted_image_buffer), mimetype='image/png', as_attachment=True, download_name=_decrypted_filename or "decrypted.png")

@app.route("/text_encrypt", methods=["POST"])
def text_encrypt_route():
    global _encrypted_text, _original_text_length, _encrypted_text_length, _decrypted_text
    _decrypted_text = None
    plain_text = request.form.get('plain_text', '').strip()
    key_raw = request.form.get('key', '')
    key_clean = normalize_key_for_storage(key_raw)
    if len(key_clean) != 25:
        return "<script>alert('Kľúč musí mať 25 znakov A-Z, 0-9.'); window.history.back();</script>"
    if not plain_text:
        return "<script>alert('Zadaj text.'); window.history.back();</script>"
    try:
        encrypted_text = text_encrypt(plain_text, key_clean)
        _encrypted_text = encrypted_text
        _original_text_length = len(plain_text)
        _encrypted_text_length = len(encrypted_text)
        save_text_history(plain_text, key_clean, encrypted_text)
        return render_template_string(INDEX_HTML, encrypted_text=encrypted_text, original_length=_original_text_length, encrypted_length=_encrypted_text_length)
    except Exception as e:
        # json.dumps bezpečne escapuje uvodzovky/</script> a pod. -> zabraňuje reflected XSS
        return f"<script>alert({json.dumps('Chyba: ' + str(e))}); window.history.back();</script>"

@app.route("/text_decrypt", methods=["POST"])
def text_decrypt_route():
    global _decrypted_text, _encrypted_text
    _encrypted_text = None
    encrypted_text = request.form.get('encrypted_text', '').strip()
    key_raw = request.form.get('key', '')
    key_clean = normalize_key_for_storage(key_raw)
    if len(key_clean) != 25:
        return "<script>alert('Kľúč musí mať 25 znakov A-Z, 0-9.'); window.history.back();</script>"
    if not encrypted_text:
        return "<script>alert('Zadaj zašifrovaný text.'); window.history.back();</script>"
    try:
        decrypted_text = text_decrypt(encrypted_text, key_clean)
        _decrypted_text = decrypted_text
        return render_template_string(INDEX_HTML, decrypted_text=decrypted_text)
    except Exception as e:
        return f"<script>alert({json.dumps('Chyba: ' + str(e))}); window.history.back();</script>"

@app.route("/history/list")
def history_list():
    if not HISTORY_ROOT.exists(): return jsonify({"folders": []})
    result = []
    for top_dir in ["TextCrypt", "ImgCrypt"]:
        top_path = HISTORY_ROOT / top_dir
        if top_path.is_dir():
            for item in top_path.iterdir():
                if item.is_dir() and item.name.startswith("Encrypted_"):
                    try:
                        dt = datetime.fromtimestamp(item.stat().st_ctime).strftime("%Y-%m-%d %H:%M:%S")
                        result.append({
                            "path": str(item.relative_to(HISTORY_ROOT)).replace("\\", "/"),
                            "name": item.name, "created": dt
                        })
                    except: continue
    result.sort(key=lambda x: x["created"], reverse=True)
    return jsonify({"folders": result})

@app.route("/history/delete/<path:rel_path>", methods=["POST"])
def history_delete(rel_path):
    # PÔVODNÝ KÓD tu mal path traversal: "../../../ľubovoľný/priečinok" by sa dal
    # zmazať cez shutil.rmtree, keďže rel_path sa nikde neoveroval. Teraz striktne
    # vyžadujeme presne tvar "TextCrypt/Encrypted_..." alebo "ImgCrypt/Encrypted_...",
    # a navyše overíme, že výsledná cesta reálne leží pod HISTORY_ROOT.
    if not re.fullmatch(r"(TextCrypt|ImgCrypt)/Encrypted_[0-9A-Za-z_]+", rel_path):
        return jsonify({"error": "Neplatná cesta"}), 400
    try:
        history_root_resolved = HISTORY_ROOT.resolve()
        full_path = (HISTORY_ROOT / rel_path).resolve()
        if history_root_resolved not in full_path.parents:
            return jsonify({"error": "Neplatná cesta"}), 400
        if full_path.is_dir():
            shutil.rmtree(full_path)
            return jsonify({"status": "ok"})
        return jsonify({"error": "Nie je priečinok"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# === 🔥 DÔLEŽITÉ: SHUTDOWN ENDPOINT (korektné ukončenie) ===
@app.route("/shutdown", methods=["POST"])
def shutdown():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError("Nie je spustený Werkzeug server")
    func()
    return "Server sa ukončuje...", 200


# === HTML === (100% self-contained — žiadne externé zdroje)
INDEX_HTML = """
<!doctype html>
<html lang="sk">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Titan Crypt</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", "Helvetica Neue", Arial, sans-serif;
      background: #0f1220;
      color: #eaf0ff;
      padding: 20px;
      margin: 0;
    }
    .card {
      background: #151823;
      padding: 18px;
      border-radius: 12px;
      border: 1px solid #2b3440;
      max-width: 900px;
      margin: 0 auto 20px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    label {
      display: block;
      margin-top: 14px;
      color: #aab6d1;
      font-weight: 500;
    }
    input[type=text], textarea, input[type=file] {
      width: 100%;
      padding: 10px;
      border-radius: 8px;
      background: #0e1117;
      border: 1px solid #26303b;
      color: #eaf0ff;
      font-size: 14px;
    }
    textarea {
      min-height: 120px;
      resize: vertical;
    }
    .row { display: flex; gap: 10px; margin-top: 12px; align-items: end; }
    .row > * { flex: 1; }
    button {
      padding: 10px 16px;
      border-radius: 8px;
      border: none;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .small { padding: 8px 12px; font-size: 0.9rem; }
    .note { font-size: 0.9rem; color: #97a6c2; margin-top: 8px; }
    .img-preview-container {
      margin-top: 12px;
      position: relative;
      display: inline-block;
      border: 1px solid #26303b;
      border-radius: 8px;
      overflow: hidden;
    }
    .img-preview { max-width: 100%; display: block; }
    .download-btn-overlay {
      position: absolute;
      top: 10px;
      right: 10px;
      z-index: 10;
      background: rgba(21, 24, 35, 0.95);
      border: 1px solid #2b3440;
      border-radius: 6px;
    }
    .dice-btn {
      background: #2b3140;
      padding: 10px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 1.3rem;
      display: flex;
      align-items: center;
      justify-content: center;
      width: 46px;
      height: 46px;
      flex-shrink: 0;
    }
    .key-input-container {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    .error-message {
      color: #ff6b6b;
      font-size: 0.85rem;
      margin-top: 6px;
      display: none;
      align-items: center;
      gap: 6px;
    }
    .section { margin-top: 28px; border-top: 1px solid #28313e; padding-top: 28px; }
    .copy-text-btn {
      background: #2b3140;
      padding: 8px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.95rem;
      margin-top: 10px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .download-btn {
      background: #2e8b57 !important;
      color: white;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .stop-btn {
      background: #d32f2f !important;
      color: white;
      padding: 8px 14px !important;
      margin-top: 10px;
    }
    .speed-radio {
      display: flex;
      gap: 16px;
      margin-top: 10px;
      font-size: 0.95rem;
      color: #aab6d1;
    }
    .speed-radio label {
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
    }
    .progress-container {
      margin-top: 14px;
      display: none;
    }
    .progress-bar {
      height: 24px;
      background: #2b3440;
      border-radius: 6px;
      overflow: hidden;
    }
    .progress-fill {
      height: 100%;
      width: 0%;
      background: #2e8b57;
      transition: width 0.3s;
    }
    .progress-status {
      font-size: 0.9rem;
      color: #aab6d1;
      margin-top: 6px;
    }

    /* HISTORY */
    .history-item {
      background: #1a1e2b;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 10px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-left: 4px solid #2e8b57;
    }
    .history-item-text { border-left-color: #8b5cf6; }
    .history-item-name {
      font-weight: 600;
      color: #eaf0ff;
      font-size: 1.05rem;
    }
    .history-item-time {
      font-size: 0.85rem;
      color: #97a6c2;
    }
    .delete-btn {
      background: #d32f2f;
      color: white;
      border: none;
      border-radius: 6px;
      width: 32px;
      height: 32px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      font-size: 0.95rem;
      flex-shrink: 0;
    }

    /* Hlavný nadpis */
    h2 {
      color: #2e8b57;
      text-align: center;
      margin: 0 0 16px;
      font-weight: 700;
    }
  </style>
</head>
<body>

<!-- Logo (inline SVG – žiadne externé) -->
<div style="text-align: center; margin-bottom: 24px;">
  <img src="static/TitanCryptLogo2.png"
      alt="Titan Crypt Logo"
      width="128"
      height="128"
      style="border-radius: 10px; border: 2px solid #ff0000;">
  <div style="margin-top: 10px; font-size: 1.4rem; font-weight: bold; color: #eaf0ff;">Titan Crypt</div>
</div>

<div style="text-align: right; margin-bottom: 15px;">
  <button id="history-toggle" style="
    background: #2b3440; border: none; color: #aab6d1; padding: 8px 16px;
    border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 500;
  ">☰ História</button>
</div>

<div id="history-panel" class="card" style="display: none;">
  <h3 style="margin-top: 0; color: #aab6d1;">História šifrovania</h3>
  <div id="history-content" style="margin-top: 14px;">
    <p style="color: #97a6c2;">Načítavam...</p>
  </div>
</div>

<div class="card section">
  <h2>ImgCrypt</h2>
  <h3>1) Šifrovanie obrázka → súbory</h3>
  <div id="encrypt-section">
    <label>Vyber obrázok (PNG odporúčané):</label>
    <input type="file" id="encrypt-image" accept="image/*">

    <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
    <div class="key-input-container">
      <input type="text" id="encrypt-key" placeholder="Napr. ABC12..." maxlength="29" style="flex: 1; min-width: 250px;">
      <button type="button" class="dice-btn" onclick="generateRandomKey()">🎲</button>
      <button class="copy-btn" type="button" onclick="copyEncryptionKey()" style="padding: 8px 12px; background: #2b3140;">📋 Kopírovať</button>
      <button class="small" type="button" onclick="startEncrypt()" id="encrypt-submit-btn" disabled>Zašifrovať</button>
    </div>

    <div class="error-message" id="key-error">
      <span>!</span>
      <span>Kľúč musí obsahovať presne 25 znakov (A-Z, 0-9)</span>
    </div>
    <div style="color:red; font-size: 20px;" class="note"><center>!! SKOPÍRUJ KĽÚČ - potrebný pre dešifrovanie !!<center></div>
    <div class="note">Pomlčky sa automaticky vkladajú každých 5 znakov.</div>
    
    <label>Režim spracovania (RAM optimalizácia):</label>
    <div class="speed-radio">
      <label><input type="radio" name="speed_mode" value="high"> High</label>
      <label><input type="radio" name="speed_mode" value="medium" checked> Medium</label>
      <label><input type="radio" name="speed_mode" value="slow"> Slow</label>
      <label><input type="radio" name="speed_mode" value="veryslow"> Very slow</label>
    </div>

    <div class="progress-container" id="encrypt-progress">
      <div class="progress-bar"><div class="progress-fill" id="encrypt-bar"></div></div>
      <div class="progress-status" id="encrypt-status">0% (odhad: --s)</div>
      <button class="small stop-btn" id="encrypt-stop-btn" onclick="cancelEncryptTask()">⏹ Zrušiť</button>
    </div>
  </div>

  <hr style="margin: 20px 0; border-color: #28313e;">

  <h3>2) Dešifrovanie súborov → obrázok</h3>
  <div id="decrypt-section">
    <label>Nahraj zašifrovaný obrázok (.png):</label>
    <input type="file" id="decrypt-image-file" accept=".png">
    <label>Nahraj dešifrovací kľúč (.key):</label>
    <input type="file" id="decrypt-key-file" accept=".key">

    <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
    <div class="key-input-container">
      <input type="text" id="decrypt-key" placeholder="Vlož kľúč pre dešifrovanie" maxlength="29" style="flex: 1; min-width: 220px;">
      <button class="copy-btn" type="button" onclick="copyDecryptionKey()" style="padding: 8px 12px; background: #2b3140;">📋 Kopírovať</button>
      <button class="small" type="button" onclick="startDecrypt()" id="decrypt-submit-btn" disabled>Dešifrovať</button>
    </div>

    <div class="error-message" id="decrypt-key-error">
      <span>!</span>
      <span>Kľúč musí obsahovať presne 25 znakov (A-Z, 0-9)</span>
    </div>

    <label>Režim spracovania:</label>
    <div class="speed-radio">
      <label><input type="radio" name="decrypt_speed_mode" value="high"> High</label>
      <label><input type="radio" name="decrypt_speed_mode" value="medium" checked> Medium</label>
      <label><input type="radio" name="decrypt_speed_mode" value="slow"> Slow</label>
      <label><input type="radio" name="decrypt_speed_mode" value="veryslow"> Very slow</label>
    </div>

    <div class="progress-container" id="decrypt-progress">
      <div class="progress-bar"><div class="progress-fill" id="decrypt-bar"></div></div>
      <div class="progress-status" id="decrypt-status">0% (odhad: --s)</div>
      <button class="small stop-btn" id="decrypt-stop-btn" onclick="cancelDecryptTask()">⏹ Zrušiť</button>
    </div>
  </div>

  {% if enc_success %}
    <hr>
    <h3 style="color: #2e8b57;">Šifrovanie úspešné! ✅</h3>
    <div style="margin-top:14px; display:flex; flex-wrap:wrap; gap:12px;">
      <a href="/download_encrypted_image" download="encrypted_image.png" style="text-decoration:none;">
        <button class="small download-btn">⬇️ Šifrovaný obrázok (.png)</button>
      </a>
      <a href="/download_decryption_key" download="decryption_key.key" style="text-decoration:none;">
        <button class="small download-btn">⬇️ Dešifrovací kľúč (.key)</button>
      </a>
    </div>
    <div class="note" style="margin-top:10px; background: #2b1a1a; padding: 10px; border-radius: 6px;">
      🔒 <strong>Ulož si oba súbory!</strong> Bez dešifrovacieho kľúča nebude možné obrázok obnoviť.
    </div>
  {% endif %}

  {% if show_decrypted_image %}
    <hr>
    <h3>Dešifrovaný obrázok</h3>
    <div class="img-preview-container">
      <img src="/preview_decrypted" class="img-preview" alt="Dešifrovaný obrázok">
      <a href="/download_decrypted" download="{{ filename }}" class="download-btn-overlay">
        <button class="small" style="padding:6px 12px; font-size:0.9rem;">⬇️ Stiahnuť</button>
      </a>
    </div>
  {% endif %}
</div>

<div class="card section">
  <h2>TextCrypt</h2>

  <form method="post" action="/text_encrypt" id="textEncryptForm" style="margin-bottom:28px;">
    <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
    <div class="key-input-container">
      <input type="text" id="text-key" name="key" placeholder="Napr. ABC12..." required maxlength="29" style="flex: 1; min-width: 250px;">
      <button type="button" class="dice-btn" onclick="generateTextRandomKey()">🎲</button>
      <button class="copy-btn" type="button" onclick="copyTextKey()" style="padding: 8px 12px; background: #2b3140;">📋 Kopírovať</button>
      <button class="small" type="submit">🔒 Zašifrovať</button>
    </div>
    <div class="error-message" id="text-key-error" style="margin-top:8px;">
      <span>!</span>
      <span>Kľúč musí obsahovať presne 25 znakov</span>
    </div>

    <label>Text na zašifrovanie (podporuje diakritiku):</label>
    <textarea id="plain-text" name="plain_text" placeholder="Zadaj text na zašifrovanie..." required></textarea>
  </form>

  {% if encrypted_text %}
    <hr>
    <h3>Zašifrovaný text:</h3>
    <textarea id="encrypted-text-display" readonly>{{ encrypted_text }}</textarea>
    <button class="copy-text-btn" onclick="copyEncryptedText()">📋 Kopírovať</button>
    <div class="note" style="margin-top:8px;">
      Dĺžka: {{ original_length }} → {{ encrypted_length }} znakov
    </div>
  {% endif %}

  <hr>

  <form method="post" action="/text_decrypt" id="textDecryptForm">
    <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
    <div class="key-input-container">
      <input type="text" id="decrypt-text-key" name="key" placeholder="Napr. ABC12..." required maxlength="29" style="flex: 1; min-width: 250px;">
      <button class="copy-btn" type="button" onclick="copyDecryptTextKey()" style="padding: 8px 12px; background: #2b3140;">📋 Kopírovať</button>
      <button class="small" type="submit" style="background: #8b5cf6;">🔓 Dešifrovať</button>
    </div>
    <div class="error-message" id="decrypt-text-key-error" style="margin-top:8px;">
      <span>!</span>
      <span>Kľúč musí obsahovať presne 25 znakov</span>
    </div>

    <label>Zašifrovaný text na dešifrovanie:</label>
    <textarea id="encrypted-text-input" name="encrypted_text" placeholder="Vlož zašifrovaný text..." required></textarea>
  </form>

  {% if decrypted_text %}
    <hr>
    <h3>Dešifrovaný text:</h3>
    <textarea id="decrypted-text-display" readonly>{{ decrypted_text }}</textarea>
    <button class="copy-text-btn" onclick="copyDecryptedText()">📋 Kopírovať</button>
  {% endif %}
</div>

<script>
let currentEncryptTaskId = null;
let currentDecryptTaskId = null;

function formatKey(input) {
  let v = input.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (v.length > 25) v = v.substring(0, 25);
  input.value = v.match(/.{1,5}/g)?.join('-') || '';
}

function validateKey(input) {
  const clean = input.value.replace(/-/g, '');
  const errorId = input.id === 'encrypt-key' ? 'key-error' : 'decrypt-key-error';
  const errorElement = document.getElementById(errorId);
  
  if (clean.length !== 25) {
    errorElement.style.display = 'flex';
  } else {
    errorElement.style.display = 'none';
  }
  
  // ✅ VŽDY zavolaj validáciu formulárov — nech rozhodne kombinácia súbor + kľúč
  checkEncryptFormReady();
  checkDecryptFormReady();
}

function checkEncryptFormReady() {
  const file = document.getElementById('encrypt-image').files[0];
  const key = document.getElementById('encrypt-key').value.replace(/-/g, '');
  const btn = document.getElementById('encrypt-submit-btn');
  btn.disabled = !(file && key.length === 25);
}

function checkDecryptFormReady() {
  const i = document.getElementById('decrypt-image-file').files[0];
  const k = document.getElementById('decrypt-key-file').files[0];
  const key = document.getElementById('decrypt-key').value.replace(/-/g, '');
  const btn = document.getElementById('decrypt-submit-btn');
  btn.disabled = !(i && k && key.length === 25);
}

// Math.random() nie je kryptograficky bezpečný PRNG (predvídateľný stav) -> pre
// generovanie šifrovacích kľúčov použijeme crypto.getRandomValues().
function secureRandomKeyString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  let r = '';
  for (let i = 0; i < length; i++) r += chars[bytes[i] % chars.length];
  return r;
}

function generateRandomKey() {
  const r = secureRandomKeyString(25);
  document.getElementById('encrypt-key').value = r.match(/.{1,5}/g).join('-');
  validateKey(document.getElementById('encrypt-key'));
}

function generateTextRandomKey() {
  const r = secureRandomKeyString(25);
  document.getElementById('text-key').value = r.match(/.{1,5}/g).join('-');
  document.getElementById('text-key').dispatchEvent(new Event('input'));
}

function copyEncryptionKey() {
  document.getElementById('encrypt-key').select();
  document.execCommand('copy');
}

function copyDecryptionKey() {
  document.getElementById('decrypt-key').select();
  document.execCommand('copy');
}

function copyTextKey() {
  document.getElementById('text-key').select();
  document.execCommand('copy');
}

function copyDecryptTextKey() {
  document.getElementById('decrypt-text-key').select();
  document.execCommand('copy');
}

function copyEncryptedText() {
  document.getElementById('encrypted-text-display').select();
  document.execCommand('copy');
}

function copyDecryptedText() {
  document.getElementById('decrypted-text-display').select();
  document.execCommand('copy');
}

async function startEncrypt() {
  const file = document.getElementById('encrypt-image').files[0];
  const key = document.getElementById('encrypt-key').value;
  const mode = document.querySelector('input[name="speed_mode"]:checked')?.value || 'medium';
  if (!file || key.replace(/-/g, '').length !== 25) return alert("Vyplň všetky polia správne!");
  const fd = new FormData();
  fd.append('image', file); fd.append('key', key); fd.append('speed_mode', mode);
  document.getElementById('encrypt-progress').style.display = 'block';
  try {
    const res = await fetch('/start_encrypt', {method:'POST', body:fd});
    const d = await res.json();
    if (d.error) throw new Error(d.error);
    currentEncryptTaskId = d.task_id;
    pollEncryptStatus(d.task_id);
  } catch (e) { alert("Chyba: " + e.message); resetEncryptUI(); }
}

function pollEncryptStatus(tid) {
  const bar = document.getElementById('encrypt-bar');
  const status = document.getElementById('encrypt-status');
  const iv = setInterval(async () => {
    try {
      const res = await fetch(`/status/${tid}`);
      const s = await res.json();
      if (s.error) { clearInterval(iv); alert("Chyba: "+s.error); resetEncryptUI(); }
      else if (s.done) { clearInterval(iv); resetEncryptUI(); window.location.search='?task=encrypt_success'; }
      else { bar.style.width = s.progress + '%'; status.textContent = `${s.progress}% (odhad: ${s.eta}s)`; }
    } catch (e) { clearInterval(iv); alert("Chyba pripojenia"); resetEncryptUI(); }
  }, 300);
}

function resetEncryptUI() {
  document.getElementById('encrypt-progress').style.display = 'none';
  currentEncryptTaskId = null;
}

function cancelEncryptTask() {
  if (currentEncryptTaskId) {
    fetch(`/cancel_task/${currentEncryptTaskId}`, {method:'POST'});
    resetEncryptUI();
    alert("Úloha bola zrušená.");
  }
}

async function startDecrypt() {
  const img = document.getElementById('decrypt-image-file').files[0];
  const keyf = document.getElementById('decrypt-key-file').files[0];
  const key = document.getElementById('decrypt-key').value;
  const mode = document.querySelector('input[name="decrypt_speed_mode"]:checked')?.value || 'medium';
  if (!img || !keyf || key.replace(/-/g, '').length !== 25) return alert("Vyplň všetky polia!");
  const fd = new FormData();
  fd.append('image_file', img); fd.append('key_file', keyf); fd.append('key', key); fd.append('speed_mode', mode);
  document.getElementById('decrypt-progress').style.display = 'block';
  try {
    const res = await fetch('/start_decrypt', {method:'POST', body:fd});
    const d = await res.json();
    if (d.error) throw new Error(d.error);
    currentDecryptTaskId = d.task_id;
    pollDecryptStatus(d.task_id);
  } catch (e) { alert("Chyba: " + e.message); resetDecryptUI(); }
}

function pollDecryptStatus(tid) {
  const bar = document.getElementById('decrypt-bar');
  const status = document.getElementById('decrypt-status');
  const iv = setInterval(async () => {
    try {
      const res = await fetch(`/status/${tid}`);
      const s = await res.json();
      if (s.error) { clearInterval(iv); alert("Chyba: "+s.error); resetDecryptUI(); }
      else if (s.done) { clearInterval(iv); resetDecryptUI(); window.location.search='?task=decrypt_success'; }
      else { bar.style.width = s.progress + '%'; status.textContent = `${s.progress}% (odhad: ${s.eta}s)`; }
    } catch (e) { clearInterval(iv); alert("Chyba pripojenia"); resetDecryptUI(); }
  }, 300);
}

function resetDecryptUI() {
  document.getElementById('decrypt-progress').style.display = 'none';
  currentDecryptTaskId = null;
}

function cancelDecryptTask() {
  if (currentDecryptTaskId) {
    fetch(`/cancel_task/${currentDecryptTaskId}`, {method:'POST'});
    resetDecryptUI();
    alert("Úloha bola zrušená.");
  }
}

// HISTORY
document.getElementById('history-toggle').addEventListener('click', function() {
  const p = document.getElementById('history-panel');
  p.style.display = p.style.display === 'none' ? 'block' : 'none';
  if (p.style.display === 'block') loadHistory();
});

async function loadHistory() {
  const c = document.getElementById('history-content');
  try {
    const res = await fetch('/history/list');
    const d = await res.json();
    if (d.folders?.length) {
      c.innerHTML = d.folders.map(i => `
        <div class="history-item ${i.path.startsWith('TextCrypt') ? 'history-item-text' : ''}">
          <div>
            <div class="history-item-name">${i.name}</div>
            <div class="history-item-time">${i.created}</div>
          </div>
          <button class="delete-btn" onclick="deleteHistoryItem('${i.path}')">🗑️</button>
        </div>
      `).join('');
    } else c.innerHTML = '<p style="color:#97a6c2;">Žiadna história</p>';
  } catch (e) { c.innerHTML = `<p style="color:#ff6b6b;">Chyba: ${e.message}</p>`; }
}

async function deleteHistoryItem(relPath) {
  if (!confirm("Naozaj zmazať túto položku histórie?")) return;
  try {
    const res = await fetch(`/history/delete/${encodeURIComponent(relPath)}`, {method:'POST'});
    if (res.ok) loadHistory(); else alert("Chyba pri mazaní");
  } catch (e) { alert("Chyba: " + e.message); }
}

document.addEventListener('DOMContentLoaded', function() {
  ['encrypt-key','decrypt-key','text-key','decrypt-text-key'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', function() {
        formatKey(this);      // najskôr doplní pomlčky
        validateKey(this);    // potom validuj → zavolá check...
      });
    }
  });
  document.getElementById('encrypt-image')?.addEventListener('change', checkEncryptFormReady);
  document.getElementById('decrypt-image-file')?.addEventListener('change', checkDecryptFormReady);
  document.getElementById('decrypt-key-file')?.addEventListener('change', checkDecryptFormReady);
});
</script>
</body>
</html>
"""


# === FLASK SERVER (s korektným shutdownom) ===
def run_server(port):
    global server_instance
    print(f"[SERVER] Spúšťam na http://{HOST}:{port}")
    try:
        # Použijeme make_server pre explicitný shutdown
        server_instance = make_server(HOST, port, app)
        server_instance.serve_forever()
    except Exception as e:
        if not stop_event.is_set():
            print(f"[SERVER] Chyba: {e}")


# === GUI ===
class ServerGUI:
    def __init__(self):
        self.root = tk.Tk()
        
        try:
          self.root.iconbitmap("C:/TitanCrypt/static/TitanCryptLogo2.ico")
        except Exception as TitanCryptLogo2IconError:
            print(f"Nepodarilo sa načitať ikonu pre GUI!\nCHYBA:" + TitanCryptLogo2IconError)

        self.root.title("Titan Crypt - your hiding software")
        self.root.geometry("560x260")
        self.root.configure(bg="#0d0f1a")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Centruj okno
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (560 // 2)
        y = (self.root.winfo_screenheight() // 2) - (260 // 2)
        self.root.geometry(f"560x260+{x}+{y}")

        # === LOGO (naľavo) ===
        logo_frame = tk.Frame(self.root, bg="#0d0f1a")
        logo_frame.pack(side="left", padx=(70,0), pady=10)

        self.logo_photo = None

        try:
            # Použi PIL s unikátnymi menami (bez kolízií s tkinter.font)
            from PIL import Image as PILImage, ImageTk, ImageDraw, ImageFont as PILFont
            logo_path = HISTORY_ROOT / "static" / "TitanCryptLogo2.png"
            if logo_path.exists():
                img = PILImage.open(logo_path).convert("RGBA")
                img = img.resize((128, 128), PILImage.LANCZOS)
                # Vytvor obrázok s border-radius a borderom
                bordered = PILImage.new("RGBA", (132, 132), (0, 0, 0, 0))

                bordered.paste(img, (2, 2))
                # Pridaj červený border
                draw = ImageDraw.Draw(bordered)
                draw.rounded_rectangle((0, 0, 131, 131), radius=10, outline=(255,0,0), width=2)
                self.logo_photo = ImageTk.PhotoImage(bordered)
            else:
                raise FileNotFoundError("Logo neexistuje")
        except Exception as e:
            print(f"[GUI] PNG logo sa nepodarilo načítať: {e}")
            # Fallback: vytvor logo programovo
            try:
                from PIL import Image as PILImage, ImageTk, ImageDraw
                img = PILImage.new("RGBA", (128, 128), (13, 15, 26, 255))
                draw = ImageDraw.Draw(img)
                draw.rectangle((8, 8, 120, 120), outline=(255, 0, 0), width=4)
                # Použi bezpečný font (ak arial nie je, použi default)
                try:
                    fallback_font = PILImage.ImageFont.truetype("arialbd.ttf", 64)
                except:
                    fallback_font = None
                draw.text((64, 36), "T", fill=(255, 0, 0), font=fallback_font, anchor="mm")
                self.logo_photo = ImageTk.PhotoImage(img)
            except Exception as e2:
                print(f"[GUI] Fallback logo zlyhalo: {e2}")
                self.logo_photo = None

        if self.logo_photo:
            logo_label = tk.Label(logo_frame, image=self.logo_photo, bg="#0d0f1a")
            logo_label.pack()

        # === HLAVNÝ OBSAH (napravo od loga) ===
        content_frame = tk.Frame(self.root, bg="#0d0f1a")
        content_frame.pack(side="left", fill="both", expand=True, padx=(0, 20))

        # 🟢 TU JE DÔLEŽITÉ: `font` je z tkinteru, nie z PIL!
        # Ak si ho importoval ako `from tkinter import ..., font`, tak je to OK
        title_font = font.Font(family="Segoe UI", size=16, weight="bold")
        label_font = font.Font(family="Segoe UI", size=11)

        tk.Label(
            content_frame,
            text="🛡️Titan Crypt Server",
            font=title_font,
            fg="#2e8b57",
            bg="#0d0f1a"
        ).pack(pady=(20, 5))

        self.status_label = tk.Label(
            content_frame,
            text="Server je zastavený",
            font=("Segoe UI", 11, "bold"),
            fg="#d32f2f",
            bg="#0d0f1a"
        )
        self.status_label.pack()

        self.port_label = tk.Label(
            content_frame,
            text="Port: —",
            font=("Segoe UI", 10),
            fg="#999999",
            bg="#0d0f1a"
        )
        self.port_label.pack()

        self.btn = tk.Button(
            content_frame,
            text="▶️ Spustiť server",
            command=self.toggle_server,
            bg="#2e8b57",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=20,
            height=2,
            relief="flat",
            bd=0,
            activebackground="#257a4a",
            activeforeground="white"
        )
        self.btn.pack(pady=5)


        tk.Label(
            content_frame,
            text="Verzia: Lite",
            font=("Segoe UI", 9),
            fg="#777777",
            bg="#0d0f1a"
        ).pack(side="top", pady=(0,5))

        tk.Label(
            content_frame,
            text="Stav aktualizácii: Nedostupné ❌",
            font=("Segoe UI", 9),
            fg="#777777",
            bg="#0d0f1a"
        ).pack(side="top", pady=(0,5))

        tk.Label(
            content_frame,
            text="Po spustení sa automaticky otvorí webový prehliadač",
            font=("Segoe UI", 9),
            fg="#777777",
            bg="#0d0f1a"
        ).pack(side="bottom", pady=(0,5))
        self.server_running = False






    def toggle_server(self):
        if not self.server_running:
            self.start_server()
        else:
            self.stop_server()

    def start_server(self):
        global server_thread
        if server_thread and server_thread.is_alive():
            return

        # Nájdi voľný port
        try:
            port = find_free_port(DEFAULT_PORT, MAX_PORT_ATTEMPTS)
        except RuntimeError as e:
            messagebox.showerror("Chyba", str(e))
            return

        # Spusti server v novom vlákne
        stop_event.clear()
        server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
        server_thread.start()

        # Aktualizuj GUI
        self.status_label.config(text="Spúšťam server...", fg="#ff9800")
        self.port_label.config(text=f"Port: {port}")
        self.btn.config(state="disabled")

        # Počkaj a otvor prehliadač
        def delayed_open():
            time.sleep(1.2)
            if server_thread.is_alive():
                self.root.after(0, lambda: self.on_server_ready(port))

        threading.Thread(target=delayed_open, daemon=True).start()

    def on_server_ready(self, port):
        self.server_running = True
        self.status_label.config(text="✅ Server beží", fg="#2e8b57")
        self.port_label.config(text=f"Port: {port}")
        self.btn.config(
            text="⏹️ Zastaviť server",
            bg="#d32f2f",
            activebackground="#b71c1c",
            state="normal"
        )
        webbrowser.open(f"http://{HOST}:{port}")

    def stop_server(self):
        global server_instance, server_thread
        self.status_label.config(text="Zastavujem server...", fg="#ff9800")
        self.btn.config(state="disabled")

        # 1. Použi shutdown endpoint (ak server ešte beží)
        try:
            if server_instance and server_instance.server_port:
                import urllib.request
                url = f"http://{HOST}:{server_instance.server_port}/shutdown"
                req = urllib.request.Request(url, method='POST')
                urllib.request.urlopen(req, timeout=1.5)
        except Exception as e:
            print(f"[GUI] Shutdown request zlyhal: {e}")

        # 2. Počkaj max 2 sekundy na ukončenie vlákna
        if server_thread and server_thread.is_alive():
            server_thread.join(timeout=2.0)

        # 3. ✅ KľÚČOVÉ: zruš referencie → umožni nové spustenie
        server_instance = None
        server_thread = None
        stop_event.set()  # uvoľni aj úlohy v progrese

        # 4. Aktualizuj GUI
        self.server_running = False
        self.status_label.config(text="Server zastavený", fg="#d32f2f")
        self.port_label.config(text="Port: —")
        self.btn.config(
            text="▶️ Spustiť server",
            bg="#2e8b57",
            activebackground="#257a4a",
            state="normal"
        )

    def on_closing(self):
        if self.server_running:
            if not messagebox.askyesno("Ukončiť?", "Server práve beží.\nNaozaj to chceš ukončiť?"):
                return
        self.stop_server()
        self.root.after(300, self.root.destroy)

    def run(self):
        self.root.mainloop()


# === HLAVNÝ SPUSTNÍK ===
if __name__ == "__main__":
    if USE_GUI:
        # Zabezpečíme, že priečinok existuje
        ensure_history_dirs()
        ensure_static_assets()
        gui = ServerGUI()
        gui.run()
    else:
        # Vývojársky režim
        port = find_free_port(DEFAULT_PORT, MAX_PORT_ATTEMPTS)
        print(f"[DEV] Spúšťam priamo na http://{HOST}:{port}")
        # POZOR: debug=True bolo v pôvodnom kóde zapnuté aj mimo vývoja - Werkzeug
        # debugger v tomto móde umožňuje vzdialené spustenie ľubovoľného Python kódu
        # (RCE), ak sa niekto dostane na endpoint s neošetrenou výnimkou. Necháme
        # vypnuté; zapni len ručne a lokálne, ak naozaj ladíš appku.
        app.run(host=HOST, port=port, debug=False)
