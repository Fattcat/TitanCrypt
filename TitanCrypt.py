#!/usr/bin/env python3
import io
import re
import random
from flask import Flask, request, render_template_string, redirect, url_for, flash, send_file
from PIL import Image

app = Flask(__name__)
app.secret_key = "your-secret-key-here"

def normalize_key_for_storage(raw: str) -> str:
    if raw is None:
        return ""
    s = re.sub(r'[^A-Za-z0-9]', '', raw).upper()
    return s[:25]

def generate_random_key(length=25):
    """Generate random key with A-Z0-9 characters"""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(random.choices(chars, k=length))

def xor_encrypt( bytes, key: bytes) -> bytes:
    """XOR encrypt data with key"""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def create_shuffle_mapping(width, height, seed):
    """Create deterministic shuffle mapping based on seed"""
    total_pixels = width * height
    indices = list(range(total_pixels))
    random.seed(seed)
    random.shuffle(indices)
    return indices

def apply_shuffle_to_image(img, shuffle_indices):
    """Apply shuffle mapping to create encrypted image"""
    img_rgba = img.convert("RGBA")
    width, height = img_rgba.size
    original_pixels = list(img_rgba.getdata())
    
    # Create new pixel list in shuffled order
    shuffled_pixels = [None] * len(original_pixels)
    for new_pos, original_pos in enumerate(shuffle_indices):
        shuffled_pixels[new_pos] = original_pixels[original_pos]
    
    # Create shuffled image
    shuffled_img = Image.new("RGBA", (width, height))
    shuffled_img.putdata(shuffled_pixels)
    return shuffled_img

def restore_original_image(shuffled_img, shuffle_indices):
    """Restore original image using shuffle indices"""
    shuffled_img_rgba = shuffled_img.convert("RGBA")
    width, height = shuffled_img_rgba.size
    shuffled_pixels = list(shuffled_img_rgba.getdata())
    
    # Create inverse mapping: for each original position, find where it ended up
    inverse_mapping = [0] * len(shuffle_indices)
    for new_pos, original_pos in enumerate(shuffle_indices):
        inverse_mapping[original_pos] = new_pos
    
    # Restore original pixels by placing each pixel back to its original position
    original_pixels = [None] * len(shuffled_pixels)
    for original_pos in range(len(original_pixels)):
        new_pos = inverse_mapping[original_pos]
        original_pixels[original_pos] = shuffled_pixels[new_pos]
    
    # Create original image
    original_img = Image.new("RGBA", (width, height))
    original_img.putdata(original_pixels)
    return original_img

def encode_image_to_files(img: Image.Image, key: str) -> (bytes, bytes):
    """Encrypt by shuffling pixels and XOR encrypting the mapping"""
    img_rgba = img.convert("RGBA")
    width, height = img_rgba.size
    
    # Create shuffle mapping using key as seed
    seed = sum(ord(c) for c in key) % (2**32)
    shuffle_indices = create_shuffle_mapping(width, height, seed)
    
    # Apply shuffle to create encrypted image
    shuffled_img = apply_shuffle_to_image(img, shuffle_indices)
    
    # Save shuffled image to bytes (PNG format)
    img_buffer = io.BytesIO()
    shuffled_img.save(img_buffer, format="PNG")
    shuffled_img_bytes = img_buffer.getvalue()
    
    # Create decryption key data: width, height, and shuffle mapping
    mapping_str = f"{width}:{height}:" + ','.join(map(str, shuffle_indices))
    key_bytes = mapping_str.encode('utf-8')
    
    # XOR encrypt the key data using the user's key
    user_key_bytes = key.encode('utf-8')
    encrypted_key_bytes = xor_encrypt(key_bytes, user_key_bytes)
    
    return shuffled_img_bytes, encrypted_key_bytes

def decode_files_to_image(shuffled_img_bytes: bytes, encrypted_key_bytes: bytes, user_key: str):
    """Decrypt using XOR and restore original image"""
    # XOR decrypt the key data
    user_key_bytes = user_key.encode('utf-8')
    decrypted_key_bytes = xor_encrypt(encrypted_key_bytes, user_key_bytes)
    key_str = decrypted_key_bytes.decode('utf-8')
    
    # Parse the key data
    parts = key_str.split(':', 2)
    if len(parts) != 3:
        raise ValueError("Neplatný formát dešifrovacieho kľúča")
    
    width = int(parts[0])
    height = int(parts[1])
    shuffle_str = parts[2]
    shuffle_indices = list(map(int, shuffle_str.split(',')))
    
    # Load shuffled image
    shuffled_img = Image.open(io.BytesIO(shuffled_img_bytes)).convert("RGBA")
    
    # Validate dimensions
    if shuffled_img.size != (width, height):
        raise ValueError("Nezhodujú sa rozmery obrázka")
    if len(shuffle_indices) != width * height:
        raise ValueError("Nezhoduje sa počet pixelov v kľúči")
    
    # Restore original image
    original_img = restore_original_image(shuffled_img, shuffle_indices)
    return original_img, width, height

INDEX_HTML = """
<!doctype html>
<html lang="sk">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Image ↔ EncryptedText (Pixel Shuffle)</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f1220; color:#eaf0ff; padding:20px; }
    .card { background:#151823; padding:16px; border-radius:10px; border:1px solid #2b3440; max-width:900px; margin:0 auto; }
    label { display:block; margin-top:12px; color:#aab6d1; }
    input[type=text] { width:100%; padding:8px; border-radius:6px; background:#0e1117; border:1px solid #26303b; color:#eaf0ff; }
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
    .img-preview {
      max-width:100%;
      display: block;
    }
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
    .error-icon {
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="card">
    <h2>Obrázok → Šifrovaný súbor (Pixel Shuffle) / Šifrovaný súbor → Obrázok</h2>

    <h3>1) Šifrovanie obrázka → súbory</h3>
    <form method="post" action="/encrypt" enctype="multipart/form-data" id="encryptForm">
      <label>Vyber obrázok (PNG odporúčané):</label>
      <input type="file" name="image" accept="image/*" required>
      <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
      <div class="key-input-container">
        <input type="text" id="encrypt-key" name="key" placeholder="Napr. ABC12..." required
               oninput="validateKey(this)" maxlength="29">
        <div class="key-buttons">
          <button type="button" class="dice-btn" onclick="generateRandomKey()">🎲</button>
          <button class="copy-btn" type="button" onclick="copyEncryptionKey()" style="padding:6px;font-size:0.8rem;background:#4a5568;">📋 Kopírovať</button>
        </div>
        <button class="small" type="submit" style="height:42px;padding:0 12px;">Zašifrovať</button>
      </div>
      <div class="error-message" id="key-error">
        <span class="error-icon">!</span>
        <span>Kľúč musí obsahovať presne 25 znakov (A-Z, 0-9)</span>
      </div>
      <div class="note">Pomlčky sa automaticky vkladajú každých 5 znakov. Kľúč musí mať presne 25 znakov.</div>
    </form>

    <hr style="margin-top:16px; border-color:#28313e">

    <h3>2) Dešifrovanie súborov → obrázok</h3>
    <form method="post" action="/decrypt_file" enctype="multipart/form-data">
      <label>Nahraj zašifrovaný obrázok (.png):</label>
      <input type="file" name="image_file" accept=".png" required>
      <label>Nahraj dešifrovací kľúč (.key):</label>
      <input type="file" name="key_file" accept=".key" required>
      <label>Kľúč (A–Z, 0–9; presne 25 znakov):</label>
      <div class="key-input-container">
        <input type="text" id="decrypt-key" name="key" placeholder="Vlož kľúč pre dešifrovanie" required
               oninput="validateKey(this)" maxlength="29">
        <div class="key-buttons">
          <button class="copy-btn" type="button" onclick="copyDecryptionKey()" style="padding:6px;font-size:0.8rem;background:#4a5568;">📋 Kopírovať</button>
        </div>
        <button class="small" type="submit" style="height:42px;padding:0 12px;">Dešifrovať</button>
      </div>
      <div class="error-message" id="decrypt-key-error">
        <span class="error-icon">!</span>
        <span>Kľúč musí obsahovať presne 25 znakov (A-Z, 0-9)</span>
      </div>
    </form>

    {% if enc_success and used_key %}
      <hr>
      <h3>Šifrovanie úspešné!</h3>
      <div style="margin-top:10px; display:flex; gap:8px;">
        <a href="/download_encrypted_image" download="encrypted_image.png">
          <button class="small" style="background:#8b5cf6;">Stiahnuť šifrovaný obrázok (.png)</button>
        </a>
        <a href="/download_decryption_key" download="decryption_key.key">
          <button class="small" style="background:#4a5568;">Stiahnuť dešifrovací kľúč (.key)</button>
        </a>
      </div>
      <div class="note" style="margin-top:8px;">Ulož si oba súbory! Bez dešifrovacieho kľúča nebude možné obrázok obnoviť.</div>
    {% endif %}

    {% if show_decrypted_image %}
      <hr>
      <h3>Dešifrovaný obrázok</h3>
      <div class="img-preview-container">
        <img src="/preview_decrypted" class="img-preview" alt="Dešifrovaný obrázok">
        <a href="/download_decrypted" download="{{ filename }}" class="download-btn-overlay">
          <button class="small" style="padding:4px 8px;font-size:0.8rem;">Stiahnuť</button>
        </a>
      </div>
    {% endif %}

    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="flash">{{ messages[0] }}</div>
      {% endif %}
    {% endwith %}
  </div>

  <script>
    function formatKey(input) {
      let value = input.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (value.length > 25) value = value.substring(0, 25);
      let formatted = value.match(/.{1,5}/g)?.join('-') || '';
      input.value = formatted;
      validateKey(input);
    }
    
    function validateKey(input) {
      const cleanValue = input.value.replace(/-/g, '');
      const errorId = input.id === 'encrypt-key' ? 'key-error' : 'decrypt-key-error';
      const errorElement = document.getElementById(errorId);
      if (cleanValue.length !== 25) {
        errorElement.style.display = 'flex';
        input.setCustomValidity('Kľúč musí mať presne 25 znakov');
      } else {
        errorElement.style.display = 'none';
        input.setCustomValidity('');
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
    
    // Initialize validation on page load
    document.addEventListener('DOMContentLoaded', function() {
      const encryptKey = document.getElementById('encrypt-key');
      const decryptKey = document.getElementById('decrypt-key');
      if (encryptKey) {
        encryptKey.addEventListener('input', function() {
          formatKey(this);
        });
      }
      if (decryptKey) {
        decryptKey.addEventListener('input', function() {
          formatKey(this);
        });
      }
    });
  </script>
</body>
</html>
"""

# Globálne premenné
_encrypted_image_bytes = None
_decryption_key_bytes = None
_decrypted_image_buffer = None
_decrypted_filename = None

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    global _encrypted_image_bytes, _decryption_key_bytes
    if 'image' not in request.files:
        flash("Nebol vybraný žiadny obrázok.")
        return redirect(url_for('index'))
    file = request.files['image']
    key_raw = request.form.get('key', '')
    key_clean = normalize_key_for_storage(key_raw)
    if len(key_clean) != 25:
        flash("Kľúč musí obsahovať presne 25 znakov (iba A–Z, 0–9).")
        return redirect(url_for('index'))

    try:
        img = Image.open(file.stream)
    except Exception as e:
        flash(f"Chyba pri načítaní obrázka: {e}")
        return redirect(url_for('index'))

    try:
        encrypted_img_bytes, decryption_key_bytes = encode_image_to_files(img, key_clean)
        _encrypted_image_bytes = encrypted_img_bytes
        _decryption_key_bytes = decryption_key_bytes
        return render_template_string(
            INDEX_HTML, 
            enc_success=True, 
            used_key=key_clean
        )
    except Exception as e:
        flash(f"Chyba pri šifrovaní: {e}")
        return redirect(url_for('index'))

@app.route("/download_encrypted_image")
def download_encrypted_image():
    global _encrypted_image_bytes
    if _encrypted_image_bytes is None:
        flash("Žiadny šifrovaný obrázok na stiahnutie.")
        return redirect(url_for('index'))
    return send_file(
        io.BytesIO(_encrypted_image_bytes),
        mimetype='image/png',
        as_attachment=True,
        download_name='encrypted_image.png'
    )

@app.route("/download_decryption_key")
def download_decryption_key():
    global _decryption_key_bytes
    if _decryption_key_bytes is None:
        flash("Žiadny kľúč na stiahnutie.")
        return redirect(url_for('index'))
    return send_file(
        io.BytesIO(_decryption_key_bytes),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name='decryption_key.key'
    )

@app.route("/preview_decrypted")
def preview_decrypted():
    global _decrypted_image_buffer
    if _decrypted_image_buffer is None:
        return "No decrypted image available", 404
    return send_file(
        io.BytesIO(_decrypted_image_buffer),
        mimetype='image/png'
    )

@app.route("/decrypt_file", methods=["POST"])
def decrypt_file_route():
    global _decrypted_image_buffer, _decrypted_filename
    if 'image_file' not in request.files:
        flash("Nebol nahraný šifrovaný obrázok.")
        return redirect(url_for('index'))
    if 'key_file' not in request.files:
        flash("Nebol nahraný súbor s dešifrovacím kľúčom.")
        return redirect(url_for('index'))
        
    image_file = request.files['image_file']
    key_file = request.files['key_file']
    user_key = request.form.get('key', '').strip()

    # Validate user key
    key_clean = normalize_key_for_storage(user_key)
    if len(key_clean) != 25:
        flash("Kľúč musí obsahovať presne 25 znakov (iba A–Z, 0–9).")
        return redirect(url_for('index'))

    try:
        encrypted_img_bytes = image_file.read()
        encrypted_key_bytes = key_file.read()
        if not encrypted_img_bytes:
            raise ValueError("Šifrovaný obrázok je prázdny")
        if not encrypted_key_bytes:
            raise ValueError("Súbor s kľúčom je prázdny")
    except Exception as e:
        flash(f"Chyba pri čítaní súborov: {e}")
        return redirect(url_for('index'))

    try:
        img, w, h = decode_files_to_image(encrypted_img_bytes, encrypted_key_bytes, key_clean)
    except Exception as e:
        flash(f"Chyba pri dešifrovaní: {e}")
        return redirect(url_for('index'))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    _decrypted_image_buffer = buf.getvalue()
    _decrypted_filename = f"img{w}x{h}.png"
    return render_template_string(
        INDEX_HTML, 
        show_decrypted_image=True,
        filename=_decrypted_filename
    )

@app.route("/download_decrypted")
def download_decrypted():
    global _decrypted_image_buffer, _decrypted_filename
    if _decrypted_image_buffer is None or _decrypted_filename is None:
        flash("Žiadny obrázok na stiahnutie.")
        return redirect(url_for('index'))
    return send_file(
        io.BytesIO(_decrypted_image_buffer),
        mimetype='image/png',
        as_attachment=True,
        download_name=_decrypted_filename
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)