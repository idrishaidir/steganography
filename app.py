from flask import Flask, render_template, request, send_file, jsonify
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import base64
import mimetypes
import struct
import io

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────
#  PAYLOAD HEADER FORMAT
#  [4 bytes: magic 'STGV'] [1 byte: type] [4 bytes: data length]
#  [2 bytes: filename length] [n bytes: filename] [payload bytes]
#
#  type: 0x01 = text, 0x02 = image, 0x03 = file
# ─────────────────────────────────────────────────────────────────

MAGIC      = b'STGV'
TYPE_TEXT  = 0x01
TYPE_IMAGE = 0x02
TYPE_FILE  = 0x03


# ═══════════════════════════════════════════════════════════════
#  KEY DERIVATION
# ═══════════════════════════════════════════════════════════════

def derive_keys(password: str):
    h1 = hashlib.sha256(password.encode('utf-8')).digest()
    h2 = hashlib.sha256((password + '_vigenere').encode('utf-8')).digest()
    h3 = hashlib.sha256((password + '_iv').encode('utf-8')).digest()

    aes_key      = h1
    aes_iv       = h3[:16]
    vigenere_key = ''.join(chr(ord('A') + (b % 26)) for b in h2)

    return vigenere_key, aes_key, aes_iv


# ═══════════════════════════════════════════════════════════════
#  LAYER 1 — VIGENERE CIPHER
# ═══════════════════════════════════════════════════════════════

def vigenere_encrypt(plaintext: str, key: str) -> str:
    result  = []
    key_len = len(key)
    key_idx = 0

    for ch in plaintext:
        if 32 <= ord(ch) <= 126:
            shift  = ord(key[key_idx % key_len]) - ord('A')
            new_ch = chr((ord(ch) - 32 + shift) % 95 + 32)
            result.append(new_ch)
            key_idx += 1
        else:
            result.append(ch)

    return ''.join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    result  = []
    key_len = len(key)
    key_idx = 0

    for ch in ciphertext:
        if 32 <= ord(ch) <= 126:
            shift  = ord(key[key_idx % key_len]) - ord('A')
            new_ch = chr((ord(ch) - 32 - shift) % 95 + 32)
            result.append(new_ch)
            key_idx += 1
        else:
            result.append(ch)

    return ''.join(result)


# ═══════════════════════════════════════════════════════════════
#  LAYER 2 — AES-256 CBC
# ═══════════════════════════════════════════════════════════════

def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))


def aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)


# ═══════════════════════════════════════════════════════════════
#  DOUBLE-LAYER  (TEXT: Vigenere → AES-256)
# ═══════════════════════════════════════════════════════════════

def double_encrypt(plaintext: str, password: str) -> bytes:
    vigenere_key, aes_key, aes_iv = derive_keys(password)
    vigenere_out = vigenere_encrypt(plaintext, vigenere_key)
    aes_out      = aes_encrypt(vigenere_out.encode('utf-8'), aes_key, aes_iv)
    return aes_out


def double_decrypt(ciphertext_bytes: bytes, password: str) -> str:
    vigenere_key, aes_key, aes_iv = derive_keys(password)
    aes_out   = aes_decrypt(ciphertext_bytes, aes_key, aes_iv)
    plaintext = vigenere_decrypt(aes_out.decode('utf-8'), vigenere_key)
    return plaintext


# ═══════════════════════════════════════════════════════════════
#  BINARY ENCRYPT  (image & file: AES-256 saja)
# ═══════════════════════════════════════════════════════════════

def binary_encrypt(data: bytes, password: str) -> bytes:
    _, aes_key, aes_iv = derive_keys(password)
    return aes_encrypt(data, aes_key, aes_iv)


def binary_decrypt(data: bytes, password: str) -> bytes:
    _, aes_key, aes_iv = derive_keys(password)
    return aes_decrypt(data, aes_key, aes_iv)


# ═══════════════════════════════════════════════════════════════
#  PAYLOAD BUILDER / PARSER
# ═══════════════════════════════════════════════════════════════

def build_payload(payload_type: int, data: bytes, filename: str = '') -> bytes:
    fname_bytes = filename.encode('utf-8')
    header  = MAGIC
    header += struct.pack('>B', payload_type)
    header += struct.pack('>I', len(data))
    header += struct.pack('>H', len(fname_bytes))
    header += fname_bytes
    return header + data


def parse_payload(data: bytes):
    if data[:4] != MAGIC:
        raise ValueError("Magic bytes tidak ditemukan — gambar tidak mengandung data tersembunyi.")
    offset    = 4
    ptype     = struct.unpack('>B', data[offset:offset+1])[0]; offset += 1
    data_len  = struct.unpack('>I', data[offset:offset+4])[0]; offset += 4
    fname_len = struct.unpack('>H', data[offset:offset+2])[0]; offset += 2
    filename  = data[offset:offset+fname_len].decode('utf-8');  offset += fname_len
    raw       = data[offset:offset+data_len]
    return ptype, filename, raw


# ═══════════════════════════════════════════════════════════════
#  LSB STEGANOGRAFI — SEPENUHNYA IN-MEMORY
# ═══════════════════════════════════════════════════════════════

def encode_lsb(carrier_stream, payload_bytes: bytes) -> io.BytesIO:
    """Terima file-like object, kembalikan BytesIO berisi PNG hasil encode."""
    img = Image.open(carrier_stream).convert('RGB')
    w, h = img.size
    capacity = (w * h * 3) // 8 - 4

    if len(payload_bytes) > capacity:
        raise ValueError(f"Payload terlalu besar ({len(payload_bytes)} bytes). Kapasitas: {capacity} bytes.")

    bits      = ''.join(format(b, '08b') for b in payload_bytes)
    full_bits = format(len(bits), '032b') + bits

    pixels     = list(img.getdata())
    new_pixels = []
    bit_idx    = 0
    total_bits = len(full_bits)

    for pixel in pixels:
        channels = list(pixel)
        for i in range(3):
            if bit_idx < total_bits:
                channels[i] = (channels[i] & ~1) | int(full_bits[bit_idx])
                bit_idx += 1
        new_pixels.append(tuple(channels))

    out = Image.new('RGB', img.size)
    out.putdata(new_pixels)

    buf = io.BytesIO()
    out.save(buf, format='PNG')
    buf.seek(0)
    return buf


def decode_lsb(image_stream) -> bytes:
    """Terima file-like object, kembalikan payload bytes."""
    img      = Image.open(image_stream).convert('RGB')
    all_bits = ""

    for pixel in img.getdata():
        for channel in pixel:
            all_bits += str(channel & 1)
            if len(all_bits) >= 32:
                bit_count = int(all_bits[:32], 2)
                if len(all_bits) >= 32 + bit_count:
                    payload_bits = all_bits[32:32 + bit_count]
                    return bytes(int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8))
    return b""


# ═══════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encode/text', methods=['POST'])
def encode_text():
    try:
        carrier  = request.files['image']
        text     = request.form['text']
        password = request.form['password']

        encrypted  = double_encrypt(text, password)
        payload    = build_payload(TYPE_TEXT, encrypted)
        output_buf = encode_lsb(carrier.stream, payload)

        return send_file(output_buf, mimetype='image/png',
                         as_attachment=True, download_name='encoded.png')
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/encode/image', methods=['POST'])
def encode_image_route():
    try:
        carrier  = request.files['carrier']
        secret   = request.files['secret_image']
        password = request.form['password']

        if not password:
            return jsonify({'error': 'Password tidak boleh kosong.'}), 400

        # Baca langsung dari stream — tidak ada file yang disimpan
        secret_bytes = secret.stream.read()
        encrypted    = binary_encrypt(secret_bytes, password)
        payload      = build_payload(TYPE_IMAGE, encrypted, filename=secret.filename)
        output_buf   = encode_lsb(carrier.stream, payload)

        return send_file(output_buf, mimetype='image/png',
                         as_attachment=True, download_name='stegovault_encoded.png')
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/encode/file', methods=['POST'])
def encode_file_route():
    try:
        carrier     = request.files['carrier']
        secret_file = request.files['secret_file']
        password    = request.form['password']

        if not password:
            return jsonify({'error': 'Password tidak boleh kosong.'}), 400

        # Baca langsung dari stream — tidak ada file yang disimpan
        file_bytes = secret_file.stream.read()
        encrypted  = binary_encrypt(file_bytes, password)
        payload    = build_payload(TYPE_FILE, encrypted, filename=secret_file.filename)
        output_buf = encode_lsb(carrier.stream, payload)

        return send_file(output_buf, mimetype='image/png',
                         as_attachment=True, download_name='stegovault_encoded.png')
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/decode', methods=['POST'])
def decode():
    try:
        file     = request.files['image']
        password = request.form['password']

        if not password:
            return jsonify({'error': 'Password tidak boleh kosong.'}), 400

        # Decode langsung dari stream upload
        raw_payload = decode_lsb(file.stream)
        ptype, filename, encrypted_data = parse_payload(raw_payload)

    except Exception as e:
        return jsonify({'error': 'Gagal membaca payload: ' + str(e)}), 400

    try:
        if ptype == TYPE_TEXT:
            plaintext = double_decrypt(encrypted_data, password)
            return jsonify({'type': 'text', 'content': plaintext})

        elif ptype == TYPE_IMAGE:
            decrypted = binary_decrypt(encrypted_data, password)
            mime      = mimetypes.guess_type(filename)[0] or 'image/png'
            b64       = base64.b64encode(decrypted).decode('utf-8')
            # Kirim langsung via base64 — tidak ada file yang disimpan
            return jsonify({
                'type'    : 'image',
                'filename': filename,
                'mime'    : mime,
                'preview' : f'data:{mime};base64,{b64}',
            })

        elif ptype == TYPE_FILE:
            decrypted = binary_decrypt(encrypted_data, password)
            mime      = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            b64       = base64.b64encode(decrypted).decode('utf-8')
            # Kirim sebagai base64 — tidak ada file yang disimpan
            return jsonify({
                'type'    : 'file',
                'filename': filename,
                'mime'    : mime,
                'size'    : len(decrypted),
                'data'    : b64,          # frontend pakai ini untuk trigger download
            })

    except Exception:
        return jsonify({'error': 'Dekripsi gagal — password salah atau data korup.'}), 400

    return jsonify({'error': 'Tipe payload tidak dikenal.'}), 400


if __name__ == '__main__':
    app.run(debug=True, port=5001)