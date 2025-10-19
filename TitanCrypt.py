#!/usr/bin/env python3
import base64
import io
import re
from flask import Flask, request, render_template_string, redirect, url_for, flash, send_file

from PIL import Image

app = Flask(__name__)
app.secret_key = "your-secret-key-here"

def normalize_key_for_storage(raw: str) -> str:
    if raw is None:
        return ""
    s = re.sub(r'[^A-Za-z0-9]', '', raw).upper()
    return s[:25]

def xor_bytes(data: bytes, key_bytes: bytes) -> bytes:
    if not key_bytes:
        raise ValueError("Kľúč nesmie byť prázdny")
    out = bytearray(len(data))
    klen = len(key_bytes)
    for i, b in enumerate(data):
        out[i] = b ^ key_bytes[i % klen]
    return bytes(out)

def encode_image_to_text(img: Image.Image, key: str) -> str:
    img_rgba = img.convert("RGBA")
    key_bytes = key.encode('ascii')
    raw = img_rgba.tobytes()
    xored = xor_bytes(raw, key_bytes)
    b64 = base64.b64encode(xored).decode('ascii')
    w, h = img_rgba.size
    return f"{w}:{h}:RGBA:{b64}"

def decode_text_to_image(text: str, key: str):
    text = re.sub(r'\s+', '', text)
    parts = text.split(':', 3)
    if len(parts) != 4:
        raise ValueError("Neplatný formát – očakávané WIDTH:HEIGHT:MODE:BASE64DATA")
    w_s, h_s, mode, b64 = parts
    w = int(w_s)
    h = int(h_s)

    missing_padding = len(b64) % 4
    if missing_padding:
        b64 += '=' * (4 - missing_padding)

    key_bytes = key.encode('ascii')
    try:
        decoded = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise ValueError(f"Neplatný Base64: {e}")

    raw = xor_bytes(decoded, key_bytes)
    expected_bytes = w * h * 4  # RGBA
    if len(raw) != expected_bytes:
        raise ValueError(f"Nezhoduje sa dĺžka dát: očakávaných {expected_bytes}, máme {len(raw)} bajtov")

    img = Image.frombytes("RGBA", (w, h), raw)
    return img, w, h

INDEX_HTML = """
<!doctype html>
<html lang="sk">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Image ↔ EncryptedText (XOR)</title>
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
    .img-preview { margin-top:8px; max-width:100%; border:1px solid #26303b; border-radius:6px; }
    .flash { color:#ffcc66; margin-top:8px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Obrázok → Šifrovaný text (XOR) / Šifrovaný text → Obrázok</h2>

    <h3>1) Šifrovanie obrázka → text</h3>
    <form method="post" action="/encrypt" enctype="multipart/form-data">
      <label>Vyber obrázok (PNG odporúčané):</label>
      <input type="file" name="image" accept="image/*" required>
      <label>Kľúč (A–Z, 0–9; max 25 znakov):</label>
      <div class="row">
        <input type="text" id="encrypt-key" name="key" placeholder="Napr. ABC12..." required
               oninput="formatKey(this)" maxlength="29">
        <button class="small" type="submit">Zašifrovať</button>
      </div>
      <div class="note">Pomlčky sa automaticky vkladajú každých 5 znakov. Interný kľúč obsahuje len A–Z0–9 (max 25).</div>
    </form>

    <hr style="margin-top:16px; border-color:#28313e">

    <h3>2) Dešifrovanie textu → obrázok</h3>
    <form method="post" action="/decrypt_file" enctype="multipart/form-data">
      <label>Nahraj .txt súbor so zašifrovaným textom:</label>
      <input type="file" name="text_file" accept=".txt" required>
      <label>Kľúč:</label>
      <div class="row">
        <input type="text" name="key" placeholder="Kľúč pre dešifrovanie" required
               oninput="formatKey(this)" maxlength="29">
        <button class="small" type="submit">Dešifrovať zo súboru</button>
      </div>
    </form>

    {% if enc_success and used_key %}
      <hr>
      <h3>Šifrovanie úspešné!</h3>
      <div style="margin-top:10px;">
        <a href="/download_encrypted" download="encrypted.txt">
          <button class="small" style="background:#8b5cf6;">Stiahnuť šifrovaný text (.txt)</button>
        </a>
      </div>
      <div class="note">Použi tento súbor a kľúč na dešifrovanie.</div>
    {% endif %}

    {% if image_data_url and filename %}
      <hr>
      <h3>Dešifrovaný obrázok</h3>
      <img src="{{ image_data_url }}" class="img-preview">
      <div style="margin-top:8px">
        <a href="/download_decrypted" download="{{ filename }}"><button class="small">Stiahnuť {{ filename }}</button></a>
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
    }
  </script>
</body>
</html>
"""

# Globálne premenné
_encrypted_text = None
_used_key = None
_decrypted_image_buffer = None
_decrypted_filename = None

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    global _encrypted_text, _used_key
    if 'image' not in request.files:
        flash("Nebol vybraný žiadny obrázok.")
        return redirect(url_for('index'))
    file = request.files['image']
    key_raw = request.form.get('key', '')
    key_clean = normalize_key_for_storage(key_raw)
    if len(key_clean) == 0 or len(key_clean) > 25:
        flash("Kľúč musí mať 1–25 znakov (iba A–Z, 0–9).")
        return redirect(url_for('index'))

    try:
        img = Image.open(file.stream).convert("RGBA")
    except Exception as e:
        flash(f"Chyba pri načítaní obrázka: {e}")
        return redirect(url_for('index'))

    try:
        out_text = encode_image_to_text(img, key_clean)
        _encrypted_text = out_text
        _used_key = key_clean
        return render_template_string(INDEX_HTML, enc_success=True, used_key=key_clean)
    except Exception as e:
        flash(f"Chyba pri šifrovaní: {e}")
        return redirect(url_for('index'))

@app.route("/download_encrypted")
def download_encrypted():
    global _encrypted_text
    if _encrypted_text is None:
        flash("Žiadny text na stiahnutie.")
        return redirect(url_for('index'))
    return send_file(
        io.BytesIO(_encrypted_text.encode('utf-8')),
        mimetype='text/plain',
        as_attachment=True,
        download_name='encrypted.txt'
    )

@app.route("/decrypt_file", methods=["POST"])
def decrypt_file_route():
    global _decrypted_image_buffer, _decrypted_filename
    if 'text_file' not in request.files:
        flash("Nebol nahraný súbor.")
        return redirect(url_for('index'))
    file = request.files['text_file']
    key_raw = request.form.get('key', '')
    key_clean = normalize_key_for_storage(key_raw)
    if len(key_clean) == 0 or len(key_clean) > 25:
        flash("Neplatný kľúč.")
        return redirect(url_for('index'))

    try:
        enc_text = file.read().decode('utf-8').strip()
        if not enc_text:
            raise ValueError("Súbor je prázdny")
    except Exception as e:
        flash(f"Chyba pri čítaní súboru: {e}")
        return redirect(url_for('index'))

    try:
        img, w, h = decode_text_to_image(enc_text, key_clean)
    except Exception as e:
        flash(f"Chyba pri dešifrovaní: {e}")
        return redirect(url_for('index'))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    data_b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    data_url = "image/png;base64," + data_b64
    filename = f"img{w}x{h}.png"

    _decrypted_image_buffer = buf.getvalue()
    _decrypted_filename = filename
    return render_template_string(INDEX_HTML, image_data_url=data_url, filename=filename)

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
