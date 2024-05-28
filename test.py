import os

from pyotp import totp
from tqdm import tqdm
from time import sleep

"""
for i in tqdm(range(100)):
    sleep(0.01)

text = ""
for char in tqdm(["a", "b", "c", "d"]):
    sleep(0.05)
    text = text + char

with tqdm("text") as pbar:
    for char in pbar:
        pbar.set_description("Processing %s" % char)
        sleep(0.7)
"""

import pyotp
import qrcode
import pyqrcode
from io import BytesIO
from PIL import Image
"""
print(b'KZWE4SVP4NYP4RFGIOJGUBXGSQKVLXZN')
print(b'KZWE4SVP4NYP4RFGIOJGUBXGSQKVLXZN'.decode('utf8'))

# Generate a secret key for the user
secret_key = pyotp.random_base32()

# Create a TOTP object with the secret key
totp = pyotp.TOTP(secret_key)

# Generate a QR code setup URI
uri = totp.provisioning_uri(name="Vault", issuer_name="CipherLocker")

# Generate a QR code image from the URI
qr = qrcode.main.QRCode(version=1, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_L)
qr.add_data(uri)
qr.make(fit=True)

buffer = BytesIO()
img = qr.make_image()
img.save(buffer, 'PNG')
buffer.seek(0)
img = Image.open(buffer)
img.show()

qrc = pyqrcode.create(uri)
print(qrc.terminal())

# Prompt the user to enter the OTP
otp = input("Enter the OTP: ")

# Verify the OTP
is_valid = totp.verify(otp)

if is_valid:
    print("OTP is valid")
else:
    print("OTP is invalid")

print(totp.secret)
"""
"""
totp_verify = pyotp.TOTP("KZWE4SVP4NYP4RFGIOJGUBXGSQKVLXZN", 6)

otp = input("Enter the OTP: ")
print(totp_verify.verify(otp))
"""

a = {"a": True, "b": False, "c": False, "d": False}
for k, v in a.items():
    print(k, v)
