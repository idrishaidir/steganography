from flask import Flask, render_template, request, send_file, jsonify
from PIL import Image
from Crypto.Cipher import AES, ChaCha20
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
#  KEY DERIVATION (Menghasilkan Kunci untuk 3 Layer)
# ═══════════════════════════════════════════════════════════════

def derive_keys(password: str):
    # Layer 1 Kunci: Vigenere
    h_vig  = hashlib.sha256((password + '_vigenere').encode('utf-8')).digest()
    # Layer 2 Kunci & IV: AES-256 CBC
    h_aes  = hashlib.sha256((password + '_aes').encode('utf-8')).digest()
    h_iv   = hashlib.sha256((password + '_aes_iv').encode('utf-8')).digest()
    # Layer 3 Kunci & Nonce: ChaCha20
    h_cc20 = hashlib.sha256((password + '_chacha').encode('utf-8')).digest()
    h_nonce= hashlib.sha256((password + '_chacha_nonce').encode('utf-8')).digest()

    vigenere_key = h_vig
    aes_key      = h_aes
    aes_iv       = h_iv[:16]
    chacha_key   = h_cc20
    chacha_nonce = h_nonce[:12]

    return vigenere_key, aes_key, aes_iv, chacha_key, chacha_nonce


# ═══════════════════════════════════════════════════════════════
#  LAYER 1 — VIGENERE CIPHER (BYTE-LEVEL)
# ═══════════════════════════════════════════════════════════════

def vigenere_encrypt_bytes(plain_bytes: bytes, key_bytes: bytes) -> bytes:
    cipher_bytes = bytearray()
    key_len = len(key_bytes)
    for idx, b in enumerate(plain_bytes):
        shift = key_bytes[idx % key_len]
        cipher_bytes.append((b + shift) % 256)
    return bytes(cipher_bytes)


def vigenere_decrypt_bytes(cipher_bytes: bytes, key_bytes: bytes) -> bytes:
    plain_bytes = bytearray()
    key_len = len(key_bytes)
    for idx, b in enumerate(cipher_bytes):
        shift = key_bytes[idx % key_len]
        plain_bytes.append((b - shift) % 256)
    return bytes(plain_bytes)


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
#  LAYER 3 — CHACHA20 STREAM CIPHER
# ═══════════════════════════════════════════════════════════════

def chacha20_encrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)


def chacha20_decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(data)


# ═══════════════════════════════════════════════════════════════
#  TRIPLE-LAYER ENCRYPTION & DECRYPTION (FOR ALL PAYLOADS)
# ═══════════════════════════════════════════════════════════════

def triple_encrypt_bytes(data_bytes: bytes, password: str) -> bytes:
    vigenere_key, aes_key, aes_iv, chacha_key, chacha_nonce = derive_keys(password)
    print("\n" + "="*30)
    print("Enkripsi")
    print("="*30)
    print(f"Data Awal (Hex) : {data_bytes[:20].hex()}...")
    # Lapis 1: Vigenere Cipher (Byte-Level)
    l1_out = vigenere_encrypt_bytes(data_bytes, vigenere_key)
    print(f"Layer 1(Vigenere Cipher) : {l1_out[:20].hex()}...")
    
    # Lapis 2: AES-256-CBC
    l2_out = aes_encrypt(l1_out, aes_key, aes_iv)
    print(f"Layer 2(AES 256) : {l2_out[:20].hex()}...")
    
    # Lapis 3: ChaCha20
    l3_out = chacha20_encrypt(l2_out, chacha_key, chacha_nonce)
    print(f"Layer 3(ChaCha20) : {l3_out[:20].hex()}...")

    print("\n" + "="*30)
    print("Enkripsi Selesai")
    print("="*30)
    return l3_out


def triple_decrypt_bytes(ciphertext_bytes: bytes, password: str) -> bytes:
    vigenere_key, aes_key, aes_iv, chacha_key, chacha_nonce = derive_keys(password)
    # Lapis 3: Dekripsi ChaCha20
    l2_in = chacha20_decrypt(ciphertext_bytes, chacha_key, chacha_nonce)
    
    # Lapis 2: Dekripsi AES-256-CBC
    l1_in = aes_decrypt(l2_in, aes_key, aes_iv)
    
    # Lapis 1: Dekripsi Vigenere Cipher (Byte-Level)
    plain_bytes = vigenere_decrypt_bytes(l1_in, vigenere_key)
    
    return plain_bytes


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
#  LSB STEGANOGRAFI 
# ═══════════════════════════════════════════════════════════════

def encode_lsb(carrier_stream, payload_bytes: bytes) -> io.BytesIO:
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

        text_bytes = text.encode('utf-8')
        encrypted  = triple_encrypt_bytes(text_bytes, password)
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

        secret_bytes = secret.stream.read()
        encrypted    = triple_encrypt_bytes(secret_bytes, password)
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

        file_bytes = secret_file.stream.read()
        encrypted  = triple_encrypt_bytes(file_bytes, password)
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

        raw_payload = decode_lsb(file.stream)
        ptype, filename, encrypted_data = parse_payload(raw_payload)

    except Exception as e:
        return jsonify({'error': 'Gagal membaca payload: ' + str(e)}), 400

    try:
        decrypted = triple_decrypt_bytes(encrypted_data, password)

        if ptype == TYPE_TEXT:
            plaintext = decrypted.decode('utf-8')
            return jsonify({'type': 'text', 'content': plaintext})

        elif ptype == TYPE_IMAGE:
            mime      = mimetypes.guess_type(filename)[0] or 'image/png'
            b64       = base64.b64encode(decrypted).decode('utf-8')
            return jsonify({
                'type'    : 'image',
                'filename': filename,
                'mime'    : mime,
                'preview' : f'data:{mime};base64,{b64}',
            })

        elif ptype == TYPE_FILE:
            mime      = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            b64       = base64.b64encode(decrypted).decode('utf-8')
            return jsonify({
                'type'    : 'file',
                'filename': filename,
                'mime'    : mime,
                'size'    : len(decrypted),
                'data'    : b64,
            })

    except Exception:
        return jsonify({'error': 'Dekripsi gagal — password salah atau data korup.'}), 400

    return jsonify({'error': 'Tipe payload tidak dikenal.'}), 400


if __name__ == '__main__':
    app.run(debug=True, port=5001)