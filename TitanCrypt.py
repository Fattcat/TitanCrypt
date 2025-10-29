import io
import re
import random
import time
import threading
from PIL import Image
from collections import defaultdict
from flask import Flask, request, render_template_string, send_file, jsonify

app = Flask(__name__)
app.secret_key = "your-secret-key-here"

# Globálne premenné pre výsledky
_encrypted_image_bytes = None
_decryption_key_bytes = None
_decrypted_image_buffer = None
_decrypted_filename = None
_encrypted_text = None
_original_text_length = 0
_encrypted_text_length = 0
_decrypted_text = None

# Sledovanie úloh
task_status = defaultdict(lambda: {"progress": 0, "eta": 0, "done": False, "error": None, "result": None, "cancelled": False})

def normalize_key_for_storage(raw: str) -> str:
    if raw is None:
        return ""
    s = re.sub(r'[^A-Za-z0-9]', '', raw).upper()
    return s[:25]

def generate_random_key(length=25):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(random.choices(chars, k=length))

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def create_shuffle_mapping(width, height, seed):
    total_pixels = width * height
    indices = list(range(total_pixels))
    random.seed(seed)
    random.shuffle(indices)
    return indices

def apply_shuffle_to_image(img, shuffle_indices):
    img_rgba = img.convert("RGBA")
    width, height = img_rgba.size
    original_pixels = list(img_rgba.getdata())
    shuffled_pixels = [None] * len(original_pixels)
    for new_pos, original_pos in enumerate(shuffle_indices):
        shuffled_pixels[new_pos] = original_pixels[original_pos]
    shuffled_img = Image.new("RGBA", (width, height))
    shuffled_img.putdata(shuffled_pixels)
    return shuffled_img

def restore_original_image(shuffled_img, shuffle_indices):
    shuffled_img_rgba = shuffled_img.convert("RGBA")
    width, height = shuffled_img_rgba.size
    shuffled_pixels = list(shuffled_img_rgba.getdata())
    inverse_mapping = [0] * len(shuffle_indices)
    for new_pos, original_pos in enumerate(shuffle_indices):
        inverse_mapping[original_pos] = new_pos
    original_pixels = [None] * len(shuffled_pixels)
    for original_pos in range(len(original_pixels)):
        new_pos = inverse_mapping[original_pos]
        original_pixels[original_pos] = shuffled_pixels[new_pos]
    original_img = Image.new("RGBA", (width, height))
    original_img.putdata(original_pixels)
    return original_img

def encode_image_to_files(img: Image.Image, key: str) -> (bytes, bytes):
    img_rgba = img.convert("RGBA")
    width, height = img_rgba.size
    seed = sum(ord(c) for c in key) % (2**32)
    shuffle_indices = create_shuffle_mapping(width, height, seed)
    shuffled_img = apply_shuffle_to_image(img, shuffle_indices)
    img_buffer = io.BytesIO()
    shuffled_img.save(img_buffer, format="PNG")
    shuffled_img_bytes = img_buffer.getvalue()
    mapping_str = f"{width}:{height}:" + ','.join(map(str, shuffle_indices))
    key_bytes = mapping_str.encode('utf-8')
    user_key_bytes = key.encode('utf-8')
    encrypted_key_bytes = xor_encrypt(key_bytes, user_key_bytes)
    return shuffled_img_bytes, encrypted_key_bytes

def decode_files_to_image(shuffled_img_bytes: bytes, encrypted_key_bytes: bytes, user_key: str):
    user_key_bytes = user_key.encode('utf-8')
    decrypted_key_bytes = xor_encrypt(encrypted_key_bytes, user_key_bytes)
    key_str = decrypted_key_bytes.decode('utf-8')
    parts = key_str.split(':', 2)
    if len(parts) != 3:
        raise ValueError("Neplatný formát dešifrovacieho kľúča")
    width = int(parts[0])
    height = int(parts[1])
    shuffle_str = parts[2]
    shuffle_indices = list(map(int, shuffle_str.split(',')))
    shuffled_img = Image.open(io.BytesIO(shuffled_img_bytes)).convert("RGBA")
    if shuffled_img.size != (width, height):
        raise ValueError("Nezhodujú sa rozmery obrázka")
    if len(shuffle_indices) != width * height:
        raise ValueError("Nezhoduje sa počet pixelov v kľúči")
    original_img = restore_original_image(shuffled_img, shuffle_indices)
    return original_img, width, height

def text_encrypt(plain_text: str, key: str) -> str:
    if not plain_text or not key:
        return ""
    text_bytes = plain_text.encode('utf-8')
    key_bytes = key.encode('utf-8')
    encrypted_bytes = xor_encrypt(text_bytes, key_bytes)
    hex_string = encrypted_bytes.hex()
    original_byte_length = len(text_bytes)
    length_hex = f"{original_byte_length:04x}"
    full_hex = length_hex + hex_string
    return full_hex

def text_decrypt(encrypted_text: str, key: str) -> str:
    if not encrypted_text or not key:
        return ""
    try:
        if not re.match(r'^[0-9a-fA-F]+$', encrypted_text):
            raise ValueError("Neplatný zašifrovaný text - obsahuje nehexadecimálne znaky")
        if len(encrypted_text) < 4:
            raise ValueError("Neplatný zašifrovaný text - chýba informácia o dĺžke")
        length_hex = encrypted_text[:4]
        original_byte_length = int(length_hex, 16)
        encrypted_hex = encrypted_text[4:]
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        if len(encrypted_bytes) > original_byte_length:
            encrypted_bytes = encrypted_bytes[:original_byte_length]
        elif len(encrypted_bytes) < original_byte_length:
            encrypted_bytes = encrypted_bytes.ljust(original_byte_length, b'\x00')
        key_bytes = key.encode('utf-8')
        decrypted_bytes = xor_encrypt(encrypted_bytes, key_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Chyba pri dešifrovaní textu: {e}")

def get_step_delay(mode):
    delays = {"high": 0.005, "medium": 0.015, "slow": 0.04, "veryslow": 0.1}
    return delays.get(mode, 0.015)

def simulate_progress_with_mode(task_id, total_steps=100, mode="medium"):
    delay = get_step_delay(mode)
    for i in range(1, total_steps + 1):
        if task_status[task_id].get("cancelled"):
            return False
        task_status[task_id]["progress"] = i
        remaining = total_steps - i
        task_status[task_id]["eta"] = round(remaining * delay, 1)
        time.sleep(delay)
    return True

def encrypt_task(task_id, file_bytes, key_raw, mode="medium"):
    try:
        key_clean = normalize_key_for_storage(key_raw)
        if len(key_clean) != 25:
            task_status[task_id]["error"] = "Kľúč musí obsahovať presne 25 znakov (iba A–Z, 0–9)."
            return
        img = Image.open(io.BytesIO(file_bytes))
        if not simulate_progress_with_mode(task_id, total_steps=80, mode=mode):
            task_status[task_id]["error"] = "Úloha zrušená používateľom."
            return
        encrypted_img_bytes, decryption_key_bytes = encode_image_to_files(img, key_clean)
        global _encrypted_image_bytes, _decryption_key_bytes
        _encrypted_image_bytes = encrypted_img_bytes
        _decryption_key_bytes = decryption_key_bytes
        task_status[task_id]["done"] = True
        task_status[task_id]["result"] = "encrypt_success"
    except Exception as e:
        task_status[task_id]["error"] = f"Chyba: {str(e)}"

def decrypt_task(task_id, image_bytes, key_bytes, user_key, mode="medium"):
    try:
        key_clean = normalize_key_for_storage(user_key)
        if len(key_clean) != 25:
            task_status[task_id]["error"] = "Kľúč musí obsahovať presne 25 znakov (iba A–Z, 0–9)."
            return
        if not simulate_progress_with_mode(task_id, total_steps=80, mode=mode):
            task_status[task_id]["error"] = "Úloha zrušená používateľom."
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

# =============== ROUTES ===============

@app.route("/", methods=["GET"])
def index():
    task = request.args.get('task')
    context = {}
    if task == "encrypt_success":
        context["enc_success"] = True
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
        threading.Thread(target=encrypt_task, args=(task_id, file_bytes, key_raw, mode), daemon=True).start()
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

# =============== DOWNLOADS ===============

@app.route("/download_encrypted_image")
def download_encrypted_image():
    global _encrypted_image_bytes
    if _encrypted_image_bytes is None:
        return "Žiadny súbor", 404
    return send_file(io.BytesIO(_encrypted_image_bytes), mimetype='image/png', as_attachment=True, download_name='encrypted_image.png')

@app.route("/download_decryption_key")
def download_decryption_key():
    global _decryption_key_bytes
    if _decryption_key_bytes is None:
        return "Žiadny súbor", 404
    return send_file(io.BytesIO(_decryption_key_bytes), mimetype='application/octet-stream', as_attachment=True, download_name='decryption_key.key')

@app.route("/preview_decrypted")
def preview_decrypted():
    global _decrypted_image_buffer
    if _decrypted_image_buffer is None:
        return "No image", 404
    return send_file(io.BytesIO(_decrypted_image_buffer), mimetype='image/png')

@app.route("/download_decrypted")
def download_decrypted():
    global _decrypted_image_buffer, _decrypted_filename
    if _decrypted_image_buffer is None:
        return "Žiadny súbor", 404
    return send_file(io.BytesIO(_decrypted_image_buffer), mimetype='image/png', as_attachment=True, download_name=_decrypted_filename or "decrypted.png")

# =============== TEXT CRYPTO ===============

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
        return render_template_string(INDEX_HTML, encrypted_text=encrypted_text, original_length=_original_text_length, encrypted_length=_encrypted_text_length)
    except Exception as e:
        return f"<script>alert('Chyba: {e}'); window.history.back();</script>"

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
        return f"<script>alert('Chyba: {e}'); window.history.back();</script>"

# =============== HTML TEMPLATE ===============

INDEX_HTML = """
<!doctype html>
<html lang="sk">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>ImgCrypt & TextCrypt</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f1220; color:#eaf0ff; padding:20px; }
    .card { background:#151823; padding:16px; border-radius:10px; border:1px solid #2b3440; max-width:900px; margin:0 auto; }
    label { display:block; margin-top:12px; color:#aab6d1; }
    input[type=text], textarea, input[type=file] { width:100%; padding:8px; border-radius:6px; background:#0e1117; border:1px solid #26303b; color:#eaf0ff; }
    textarea { min-height:100px; resize:vertical; }
    .row { display:flex; gap:8px; margin-top:10px; align-items:end; }
    .row > * { flex:1; }
    button { padding:8px 10px; border-radius:6px; border:none; background:#2e8b57; color:white; cursor:pointer; }
    .small { padding:6px 8px; font-size:0.9rem; }
    .note { font-size:0.9rem; color:#97a6c2; margin-top:8px; }
    .img-preview-container {
      margin-top:8px;
      position: relative;
      display: inline-block;
      border:1px solid #26303b;
      border-radius:6px;
      overflow: hidden;
    }
    .img-preview { max-width:100%; display: block; }
    .download-btn-overlay {
      position: absolute;
      top: 8px;
      right: 8px;
      z-index: 10;
      background: rgba(21, 24, 35, 0.9);
      border: 1px solid #2b3440;
      border-radius: 4px;
    }
    .flash { color:#ffcc66; margin-top:8px; }
    .dice-btn { 
      background:#4a5568; 
      padding:8px; 
      border-radius:6px; 
      cursor:pointer; 
      font-size:1.2rem;
      display:flex;
      align-items:center;
      justify-content:center;
      width:42px;
      height:42px;
    }
    .key-input-container {
      display: flex;
      gap: 8px;
      align-items: end;
      margin-top: 8px;
    }
    .key-buttons {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .file-input-container {
      display: flex;
      gap: 8px;
      align-items: end;
    }
    .error-message {
      color: #ff6b6b;
      font-size: 0.85rem;
      margin-top: 4px;
      display: none;
      align-items: center;
      gap: 4px;
    }
    .error-icon { font-weight: bold; }
    .section { margin-top: 24px; border-top: 1px solid #28313e; padding-top: 24px; }
    .copy-text-btn {
      background:#4a5568;
      padding:6px 10px;
      border-radius:4px;
      cursor:pointer;
      font-size:0.9rem;
      margin-top:8px;
    }
    .download-btn {
      background: #2e8b57 !important;
      color: white;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .stop-btn {
      background: #ff4d4d !important;
      color: white;
      padding: 6px 12px !important;
      margin-top: 8px;
    }
    .speed-radio {
      display: flex;
      gap: 12px;
      margin-top: 8px;
      font-size: 0.9rem;
      color: #aab6d1;
    }
    .speed-radio label {
      display: flex;
      align-items: center;
      gap: 4px;
      cursor: pointer;
    }
    .speed-radio input {
      margin: 0;
    }
    .progress-container {
      margin-top: 12px;
      display: none;
    }
    .progress-bar {
      height: 20px;
      background: #2b3440;
      border-radius: 4px;
      overflow: hidden;
    }
    .progress-fill {
      height: 100%;
      width: 0%;
      background: #2e8b57;
      transition: width 0.3s;
    }
    .progress-status {
      font-size: 0.85rem;
      color: #aab6d1;
      margin-top: 4px;
    }
  </style>
</head>
<body>
  <div class="card section">
    <center><h2>ImgCrypt</h2></center>
    <h3>1) Šifrovanie obrázka → súbory</h3>
    <div id="encrypt-section">
      <label>Vyber obrázok (PNG odporúčané):</label>
      <input type="file" id="encrypt-image" accept="image/*" style="width:450px;">
      <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
           
      <div class="key-input-container" style="display:flex; align-items:center; gap:8px; flex-wrap:nowrap;">
        <!-- Input -->
        <input type="text" id="encrypt-key" placeholder="Napr. ABC12..." maxlength="29" style="width:300px;">

        <!-- Tlačidlo s emojim a kopírovanie -->
        <button type="button" class="dice-btn" onclick="generateRandomKey()" style="padding:6px; font-size:1rem;">🎲</button>
        <button class="copy-btn" type="button" onclick="copyEncryptionKey()" style="padding:6px; font-size:0.8rem; background:#4a5568;">📋 Kopírovať</button>

        <!-- Zašifrovať -->
        <button class="small" type="button" onclick="startEncrypt()" id="encrypt-submit-btn" disabled>Zašifrovať</button>
      </div>

      <div class="error-message" id="key-error">
        <span class="error-icon">!</span>
        <span>Kľúč musí obsahovať presne 25 znakov (A-Z, 0-9)</span>
      </div>
      <div class="note">Pomlčky sa automaticky vkladajú každých 5 znakov. Kľúč musí mať presne 25 znakov.</div>

      <label>Režim spracovania (optimalizácia RAM):</label>
      <div class="speed-radio">
        <label><input type="radio" name="speed_mode" value="high"> High speed</label>
        <label><input type="radio" name="speed_mode" value="medium" checked> Medium speed</label>
        <label><input type="radio" name="speed_mode" value="slow"> Slow</label>
        <label><input type="radio" name="speed_mode" value="veryslow"> Very slow speed</label>
      </div>

      <div class="progress-container" id="encrypt-progress">
        <div class="progress-bar"><div class="progress-fill" id="encrypt-bar"></div></div>
        <div class="progress-status" id="encrypt-status">0% (odhad: --s)</div>
        <button class="small stop-btn" id="encrypt-stop-btn" onclick="cancelEncryptTask()">⏹ STOP</button>
      </div>
    </div>

    <hr style="margin-top:16px; border-color:#28313e">

    <h3>2) Dešifrovanie súborov → obrázok</h3>
    <div id="decrypt-section">
      <label>Nahraj zašifrovaný obrázok (.png):</label>
      <input type="file" id="decrypt-image-file" accept=".png" style="width:450px;">
      <label>Nahraj dešifrovací kľúč (.key):</label>
      <input type="file" id="decrypt-key-file" accept=".key" style="width:450px;">
      <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
      <div class="key-input-container">
        <input type="text" id="decrypt-key" placeholder="Vlož kľúč pre dešifrovanie" maxlength="29" style="width:250px;">
        <div class="key-buttons">
          <button class="copy-btn" type="button" onclick="copyDecryptionKey()" style="padding:6px;font-size:0.8rem;background:#4a5568;">📋 Kopírovať</button>
        </div>
        <button class="small" type="button" onclick="startDecrypt()" id="decrypt-submit-btn" disabled>Dešifrovať</button>
      </div>
      <div class="error-message" id="decrypt-key-error">
        <span class="error-icon">!</span>
        <span>Kľúč musí obsahovať presne 25 znakov (A-Z, 0-9)</span>
      </div>

      <label>Režim spracovania (optimalizácia RAM):</label>
      <div class="speed-radio">
        <label><input type="radio" name="decrypt_speed_mode" value="high"> High speed</label>
        <label><input type="radio" name="decrypt_speed_mode" value="medium" checked> Medium speed</label>
        <label><input type="radio" name="decrypt_speed_mode" value="slow"> Slow</label>
        <label><input type="radio" name="decrypt_speed_mode" value="veryslow"> Very slow speed</label>
      </div>

      <div class="progress-container" id="decrypt-progress">
        <div class="progress-bar"><div class="progress-fill" id="decrypt-bar"></div></div>
        <div class="progress-status" id="decrypt-status">0% (odhad: --s)</div>
        <button class="small stop-btn" id="decrypt-stop-btn" onclick="cancelDecryptTask()">⏹ STOP</button>
      </div>
    </div>

    {% if enc_success %}
      <hr>
      <h3>Šifrovanie úspešné!</h3>


      <div style="margin-top:10px; display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
        <a href="/download_encrypted_image" download="encrypted_image.png" style="text-decoration:none;">
          <button class="small download-btn">
            <img src="static/download.png" alt="Download" style="width:18px; height:18px; vertical-align:middle; margin-right:6px;">
            Stiahnuť šifrovaný obrázok (.png)
          </button>
        </a>

        <a href="/download_decryption_key" download="decryption_key.key" style="text-decoration:none;">
          <button class="small download-btn">
            <img src="static/download.png" alt="Download" style="width:18px; height:18px; vertical-align:middle; margin-right:6px;">
            Stiahnuť dešifrovací kľúč (.key)
          </button>
        </a>
      </div>


      <div class="note" style="margin-top:8px;">Ulož si oba súbory! Bez dešifrovacieho kľúča nebude možné obrázok obnoviť !</div>
      <div class="note" style="margin-top:8px;">Ulož si oba súbory ! .png aj .key !</div>
    {% endif %}

    {% if show_decrypted_image %}
      <hr>
      <h3>Dešifrovaný obrázok</h3>
      <div class="img-preview-container">
        <img src="/preview_decrypted" class="img-preview" alt="Dešifrovaný obrázok">
        <a href="/download_decrypted" download="{{ filename }}" class="download-btn-overlay">
          <button class="small" style="padding:4px 8px;font-size:0.8rem;">↓ Stiahnuť</button>
        </a>
      </div>
    {% endif %}
  </div>

  <div class="card section">
    <h2>TextCrypt</h2>
    <!-- Text šifrovanie zostáva rovnaké (bez loading baru) -->
    <form method="post" action="/text_encrypt" id="textEncryptForm">
      <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
      <div class="key-input-container">
        <input type="text" id="text-key" name="key" placeholder="Napr. ABC12..." required
               oninput="validateTextKey(this)" maxlength="29" style="width:300px;">
        <div class="key-buttons">
          <button type="button" class="dice-btn" onclick="generateTextRandomKey()">🎲</button>
          <button class="copy-btn" type="button" onclick="copyTextKey()" style="padding:6px;font-size:0.8rem;background:#4a5568;">📋 Kopírovať</button>
        </div>
      </div>
      <div class="error-message" id="text-key-error">
        <span class="error-icon">!</span>
        <span>Kľúč musí obsahovať presne 25 znakov (A-Z, 0-9)</span>
      </div>
      <label>Text na zašifrovanie (podporuje diakritiku):</label>
      <textarea style="height: 400px"; id="plain-text" name="plain_text" placeholder="Zadaj text na zašifrovanie..." required></textarea>
      <button class="small" type="submit" style="margin-top:12px;">Zašifrovať text</button>
    </form>

    {% if encrypted_text %}
      <hr style="margin-top:16px; border-color:#28313e">
      <h3>Zašifrovaný text:</h3>
      <textarea id="encrypted-text-display" readonly>{{ encrypted_text }}</textarea>
      <button class="copy-text-btn" onclick="copyEncryptedText()">📋 Kopírovať zašifrovaný text</button>
      <div class="note" style="margin-top:8px;">
        Dĺžka pôvodného textu: {{ original_length }} znakov | 
        Dĺžka zašifrovaného textu: {{ encrypted_length }} znakov
      </div>
    {% endif %}
    
    <hr style="margin-top:24px; border-color:#28313e">
    
    <form method="post" action="/text_decrypt" id="textDecryptForm">
      <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
      <div class="key-input-container">
        <input type="text" id="decrypt-text-key" name="key" placeholder="Napr. ABC12..." required
               oninput="validateDecryptTextKey(this)" maxlength="29" style="width:300px;">
        <div class="key-buttons">
          <button class="copy-btn" type="button" onclick="copyDecryptTextKey()" style="padding:6px;font-size:0.8rem;background:#4a5568;">📋 Kopírovať</button>
        </div>
      </div>
      <div class="error-message" id="decrypt-text-key-error">
        <span class="error-icon">!</span>
        <span>Kľúč musí obsahovať presne 25 znakov (A-Z, 0-9)</span>
      </div>
      <label>Zašifrovaný text na dešifrovanie:</label>
      <textarea id="encrypted-text-input" name="encrypted_text" placeholder="Vlož zašifrovaný text na dešifrovanie..." required></textarea>
      <button class="small" type="submit" style="margin-top:12px; background:#8b5cf6;">Dešifrovať text</button>
    </form>

    {% if decrypted_text %}
      <hr style="margin-top:16px; border-color:#28313e">
      <h3>Dešifrovaný text:</h3>
      <textarea id="decrypted-text-display" readonly>{{ decrypted_text }}</textarea>
      <button class="copy-text-btn" onclick="copyDecryptedText()">📋 Kopírovať dešifrovaný text</button>
    {% endif %}
  </div>

  <script>
    let currentEncryptTaskId = null;
    let currentDecryptTaskId = null;

    function formatKey(input) {
      let value = input.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (value.length > 25) value = value.substring(0, 25);
      let formatted = value.match(/.{1,5}/g)?.join('-') || '';
      input.value = formatted;
    }

    function validateKey(input) {
      const cleanValue = input.value.replace(/-/g, '');
      const errorId = input.id === 'encrypt-key' ? 'key-error' : 'decrypt-key-error';
      const errorElement = document.getElementById(errorId);
      const submitBtn = input.id === 'encrypt-key' ? document.getElementById('encrypt-submit-btn') : document.getElementById('decrypt-submit-btn');
      if (cleanValue.length !== 25) {
        errorElement.style.display = 'flex';
        submitBtn.disabled = true;
        submitBtn.style.opacity = 0.5;
        submitBtn.style.cursor = 'not-allowed';
      } else {
        errorElement.style.display = 'none';
        checkEncryptFormReady();
        checkDecryptFormReady();
      }
    }

    function validateTextKey(input) {
      const cleanValue = input.value.replace(/-/g, '');
      const errorElement = document.getElementById('text-key-error');
      if (cleanValue.length !== 25) {
        errorElement.style.display = 'flex';
        input.setCustomValidity('Kľúč musí mať presne 25 znakov');
      } else {
        errorElement.style.display = 'none';
        input.setCustomValidity('');
      }
    }

    function validateDecryptTextKey(input) {
      const cleanValue = input.value.replace(/-/g, '');
      const errorElement = document.getElementById('decrypt-text-key-error');
      if (cleanValue.length !== 25) {
        errorElement.style.display = 'flex';
        input.setCustomValidity('Kľúč musí mať presne 25 znakov');
      } else {
        errorElement.style.display = 'none';
        input.setCustomValidity('');
      }
    }

    function checkEncryptFormReady() {
      const file = document.getElementById('encrypt-image').files[0];
      const key = document.getElementById('encrypt-key').value.replace(/-/g, '');
      const btn = document.getElementById('encrypt-submit-btn');
      if (file && key.length === 25) {
        btn.disabled = false;
        btn.style.opacity = 1;
        btn.style.cursor = 'pointer';
      } else {
        btn.disabled = true;
        btn.style.opacity = 0.5;
        btn.style.cursor = 'not-allowed';
      }
    }

    function checkDecryptFormReady() {
      const imgFile = document.getElementById('decrypt-image-file').files[0];
      const keyFile = document.getElementById('decrypt-key-file').files[0];
      const key = document.getElementById('decrypt-key').value.replace(/-/g, '');
      const btn = document.getElementById('decrypt-submit-btn');
      if (imgFile && keyFile && key.length === 25) {
        btn.disabled = false;
        btn.style.opacity = 1;
        btn.style.cursor = 'pointer';
      } else {
        btn.disabled = true;
        btn.style.opacity = 0.5;
        btn.style.cursor = 'not-allowed';
      }
    }

    function generateRandomKey() {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let result = '';
      for (let i = 0; i < 25; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      document.getElementById('encrypt-key').value = result.match(/.{1,5}/g).join('-');
      validateKey(document.getElementById('encrypt-key'));
    }

    function generateTextRandomKey() {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let result = '';
      for (let i = 0; i < 25; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      document.getElementById('text-key').value = result.match(/.{1,5}/g).join('-');
      validateTextKey(document.getElementById('text-key'));
    }

    function copyEncryptionKey() {
      const keyInput = document.getElementById('encrypt-key');
      keyInput.select();
      document.execCommand('copy');
      alert('Šifrovací kľúč bol skopírovaný do schránky!');
    }

    function copyDecryptionKey() {
      const keyInput = document.getElementById('decrypt-key');
      keyInput.select();
      document.execCommand('copy');
      alert('Dešifrovací kľúč bol skopírovaný do schránky!');
    }

    function copyTextKey() {
      const keyInput = document.getElementById('text-key');
      keyInput.select();
      document.execCommand('copy');
      alert('Textový kľúč bol skopírovaný do schránky!');
    }

    function copyDecryptTextKey() {
      const keyInput = document.getElementById('decrypt-text-key');
      keyInput.select();
      document.execCommand('copy');
      alert('Dešifrovací textový kľúč bol skopírovaný do schránky!');
    }

    function copyEncryptedText() {
      const textArea = document.getElementById('encrypted-text-display');
      textArea.select();
      document.execCommand('copy');
      alert('Zašifrovaný text bol skopírovaný do schránky!');
    }

    function copyDecryptedText() {
      const textArea = document.getElementById('decrypted-text-display');
      textArea.select();
      document.execCommand('copy');
      alert('Dešifrovaný text bol skopírovaný do schránky!');
    }

    // =============== ENCRYPT AJAX ===============
    async function startEncrypt() {
      const fileInput = document.getElementById('encrypt-image');
      const keyInput = document.getElementById('encrypt-key');
      const speedMode = document.querySelector('input[name="speed_mode"]:checked')?.value || 'medium';
      const file = fileInput.files[0];
      const key = keyInput.value;

      if (!file || key.replace(/-/g, '').length !== 25) {
        alert("Vyplň všetky polia správne!");
        return;
      }

      const formData = new FormData();
      formData.append('image', file);
      formData.append('key', key);
      formData.append('speed_mode', speedMode);

      document.getElementById('encrypt-progress').style.display = 'block';
      document.getElementById('encrypt-stop-btn').style.display = 'inline-block';

      try {
        const res = await fetch('/start_encrypt', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        currentEncryptTaskId = data.task_id;
        pollEncryptStatus(data.task_id);
      } catch (e) {
        alert("Chyba: " + e.message);
        resetEncryptUI();
      }
    }

    function pollEncryptStatus(taskId) {
      const bar = document.getElementById('encrypt-bar');
      const status = document.getElementById('encrypt-status');
      const interval = setInterval(async () => {
        try {
          const res = await fetch(`/status/${taskId}`);
          const s = await res.json();
          if (s.error) {
            clearInterval(interval);
            alert("Chyba: " + s.error);
            resetEncryptUI();
          } else if (s.done) {
            clearInterval(interval);
            resetEncryptUI();
            window.location.href = window.location.pathname + '?task=encrypt_success';
          } else {
            bar.style.width = s.progress + '%';
            status.textContent = `${s.progress}% (odhad: ${s.eta}s)`;
          }
        } catch (e) {
          clearInterval(interval);
          alert("Chyba pripojenia");
          resetEncryptUI();
        }
      }, 300);
    }

    function resetEncryptUI() {
      document.getElementById('encrypt-progress').style.display = 'none';
      document.getElementById('encrypt-stop-btn').style.display = 'none';
      currentEncryptTaskId = null;
    }

    function cancelEncryptTask() {
      if (currentEncryptTaskId) {
        fetch(`/cancel_task/${currentEncryptTaskId}`, { method: 'POST' });
        resetEncryptUI();
        alert("Úloha bola zrušená.");
      }
    }

    // =============== DECRYPT AJAX ===============
    async function startDecrypt() {
      const imgFile = document.getElementById('decrypt-image-file').files[0];
      const keyFile = document.getElementById('decrypt-key-file').files[0];
      const key = document.getElementById('decrypt-key').value;
      const speedMode = document.querySelector('input[name="decrypt_speed_mode"]:checked')?.value || 'medium';

      if (!imgFile || !keyFile || key.replace(/-/g, '').length !== 25) {
        alert("Vyplň všetky polia správne!");
        return;
      }

      const formData = new FormData();
      formData.append('image_file', imgFile);
      formData.append('key_file', keyFile);
      formData.append('key', key);
      formData.append('speed_mode', speedMode);

      document.getElementById('decrypt-progress').style.display = 'block';
      document.getElementById('decrypt-stop-btn').style.display = 'inline-block';

      try {
        const res = await fetch('/start_decrypt', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        currentDecryptTaskId = data.task_id;
        pollDecryptStatus(data.task_id);
      } catch (e) {
        alert("Chyba: " + e.message);
        resetDecryptUI();
      }
    }

    function pollDecryptStatus(taskId) {
      const bar = document.getElementById('decrypt-bar');
      const status = document.getElementById('decrypt-status');
      const interval = setInterval(async () => {
        try {
          const res = await fetch(`/status/${taskId}`);
          const s = await res.json();
          if (s.error) {
            clearInterval(interval);
            alert("Chyba: " + s.error);
            resetDecryptUI();
          } else if (s.done) {
            clearInterval(interval);
            resetDecryptUI();
            window.location.href = window.location.pathname + '?task=decrypt_success';
          } else {
            bar.style.width = s.progress + '%';
            status.textContent = `${s.progress}% (odhad: ${s.eta}s)`;
          }
        } catch (e) {
          clearInterval(interval);
          alert("Chyba pripojenia");
          resetDecryptUI();
        }
      }, 300);
    }

    function resetDecryptUI() {
      document.getElementById('decrypt-progress').style.display = 'none';
      document.getElementById('decrypt-stop-btn').style.display = 'none';
      currentDecryptTaskId = null;
    }

    function cancelDecryptTask() {
      if (currentDecryptTaskId) {
        fetch(`/cancel_task/${currentDecryptTaskId}`, { method: 'POST' });
        resetDecryptUI();
        alert("Úloha bola zrušená.");
      }
    }

    // =============== INIT ===============
    document.addEventListener('DOMContentLoaded', function() {
      const encryptKey = document.getElementById('encrypt-key');
      const decryptKey = document.getElementById('decrypt-key');
      const textKey = document.getElementById('text-key');
      const decryptTextKey = document.getElementById('decrypt-text-key');
      const encryptImage = document.getElementById('encrypt-image');
      const decryptImageFile = document.getElementById('decrypt-image-file');
      const decryptKeyFile = document.getElementById('decrypt-key-file');

      if (encryptKey) {
        encryptKey.addEventListener('input', function() {
          formatKey(this);
          validateKey(this);
        });
        encryptImage.addEventListener('change', checkEncryptFormReady);
      }
      if (decryptKey) {
        decryptKey.addEventListener('input', function() {
          formatKey(this);
          validateKey(this);
        });
        decryptImageFile.addEventListener('change', checkDecryptFormReady);
        decryptKeyFile.addEventListener('change', checkDecryptFormReady);
      }
      if (textKey) {
        textKey.addEventListener('input', function() {
          formatKey(this);
        });
      }
      if (decryptTextKey) {
        decryptTextKey.addEventListener('input', function() {
          formatKey(this);
        });
      }
    });
  </script>
</body>
</html>
"""

# =============== MAIN ===============

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug=True)
