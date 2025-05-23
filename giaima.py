from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import base64

class GiaiMa:
    @staticmethod
    def decrypt(encrypted_data: str, key_phrase: str, iv_base64: str) -> str:
        """
        Giải mã chuỗi được mã hóa bằng AES-256-CBC và mã hóa base64.
        :param encrypted_data: Dữ liệu đã được mã hóa (chuỗi base64)
        :param key_phrase: Cụm từ khóa (password) dùng để tạo khóa AES
        :param iv_base64: IV (chuỗi base64 dài 16 byte)
        :return: Chuỗi văn bản đã giải mã hoặc thông báo lỗi
        """
        try:
            # Sinh khóa AES 256-bit từ cụm từ khóa
            secret_key = sha256(key_phrase.encode('utf-8')).digest()
            if len(secret_key) != 32:
                return "Lỗi: Khóa không hợp lệ (không phải 256-bit)."

            # Giải mã IV từ base64
            iv = base64.b64decode(iv_base64)
            if len(iv) != 16:
                return "Lỗi: IV phải dài đúng 16 byte."

            # Giải mã dữ liệu từ base64
            decoded_data = base64.b64decode(encrypted_data)
            if len(decoded_data) % AES.block_size != 0:
                return "Lỗi: Dữ liệu mã hóa không phải bội số của block size (16 byte)."

            # Tạo đối tượng giải mã AES
            cipher = AES.new(secret_key, AES.MODE_CBC, iv)

            # Giải mã và loại bỏ padding
            padded_data = cipher.decrypt(decoded_data)
            decrypted_data = unpad(padded_data, AES.block_size)

            # Giải mã thành chuỗi UTF-8
            return decrypted_data.decode('utf-8')

        except UnicodeDecodeError as e:
            return f"Lỗi giải mã UTF-8: {e}"
        except ValueError as e:
            return f"Lỗi padding hoặc dữ liệu: {e}"
        except Exception as e:
            return f"Lỗi không xác định: {e}"

