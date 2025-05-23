from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import base64
import os

class MaHoa:
    def __init__(self, key_phrase: str):
        """Khởi tạo key AES từ mật khẩu"""
        self.key = sha256(key_phrase.encode()).digest()

    def ma_hoa(self, plaintext: str) -> tuple[str, str]:
        """Mã hóa AES-256-CBC"""
        iv = os.urandom(16)  # Sinh IV ngẫu nhiên
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        # Chuyển dữ liệu sang Base64
        return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()


