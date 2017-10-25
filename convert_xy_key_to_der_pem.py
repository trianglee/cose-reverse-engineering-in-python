from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
import base64
import binascii

# Ths code generates a PEM and DER keys from the public key in https://github.com/cose-wg/Examples/blob/master/ecdsa-examples/ecdsa-01.json.
# Constants from that file -
# The public key components -
x_base64url = "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"
y_base64url = "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"

# To dump EC public key parameters from PEM format using openssl -
# openssl ec -inform pem -in public_key.pem -pubin -text -noout
# openssl ec -inform der -in public_key.der -pubin -text -noout

# Decodes a base64url string, by padding it first.
def base64url_decode(b64url):
    b64url += '=' * (4 - (len(b64url) % 4))
    return base64.urlsafe_b64decode(b64url)

# We only care about NIST P-256 curve.
ECC_CURVE = ec.SECP256R1()
# Using OpenSSL backend for "cryptography".
BACK_END = openssl.backend

# Convert the base64url components to integers.
x_bin = base64url_decode(x_base64url)
y_bin = base64url_decode(y_base64url)

x_hex = binascii.hexlify(x_bin)
y_hex = binascii.hexlify(y_bin)

print("X: " + x_hex.decode("ascii"))
print("Y: " + y_hex.decode("ascii"))

# Convert the base64url components to integers.
x = int.from_bytes(x_bin, byteorder="big")
y = int.from_bytes(y_bin, byteorder="big")

# Acquire the public key from the public components -
public_numbers = EllipticCurvePublicNumbers(x, y, ECC_CURVE)
public_key = public_numbers.public_key(backend=BACK_END)

public_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
with open("public_key.pem", "wb") as f:
    f.write(public_key_pem)

public_key_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
with open("public_key.der", "wb") as f:
    f.write(public_key_der)
