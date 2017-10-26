from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.exceptions import InvalidSignature
import base64
import binascii

# Ths code attempts to verify the signature of https://github.com/cose-wg/Examples/blob/master/ecdsa-examples/ecdsa-sig-01.json.
# Constants from that file -
# The payload that is signed and needs to be verified -
to_be_signed_hex = "846A5369676E61747572653145A2012603004054546869732069732074686520636F6E74656E742E"
# The private key used to sign -
d_base64url = "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
# The public key components to verify the signature -
x_base64url = "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"
y_base64url = "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
# The signature -
signature_hex = "6520BBAF2081D7E0ED0F95F76EB0733D667005F7467CEC4B87B9381A6BA1EDE8E00DF29F32A37230F39A842A54821FDD223092819D7728EFB9D3A0080B75380B"

# Decodes a base64url string, by padding it first.
def base64url_decode(b64url):
    b64url += '=' * (4 - (len(b64url) % 4))
    return base64.urlsafe_b64decode(b64url)

# We only care about NIST P-256 curve.
ECC_CURVE = ec.SECP256R1()
# Using OpenSSL backend for "cryptography".
BACK_END = openssl.backend

# Convert the base64url components to integers.
x = int.from_bytes(base64url_decode(x_base64url), byteorder="big")
y = int.from_bytes(base64url_decode(y_base64url), byteorder="big")
d = int.from_bytes(base64url_decode(d_base64url), byteorder="big")

# Create a private key object from the integer private key.
private_key = ec.derive_private_key(d, curve=ECC_CURVE, backend=BACK_END)
# Fetch the numbers back from the private key.
private_numbers = private_key.private_numbers()
calc_x = private_numbers.public_numbers.x
calc_y = private_numbers.public_numbers.y
calc_d = private_numbers.private_value
# Compare the input public key components to the calculated public key components.
assert(x == calc_x)
assert(y == calc_y)
assert(d == calc_d)

# Split the signature into its components.
signature_component_len = int(len(signature_hex) / 2)
signature_r_hex = signature_hex[0 : signature_component_len]
signature_s_hex = signature_hex[signature_component_len :  ]
# Convert each component from hex string to integer.
signature_r_bin = binascii.unhexlify(signature_r_hex)
signature_s_bin = binascii.unhexlify(signature_s_hex)
signature_r = int.from_bytes(signature_r_bin, "big")
signature_s = int.from_bytes(signature_s_bin, "big")
# Create a DER signature.
signature_der = encode_dss_signature(signature_r, signature_s)

# Convert to_be_signed from hex string to a byte array.
to_be_signed = binascii.unhexlify(to_be_signed_hex)

# Acquire the public key in two ways -
# From the private key -
public_key_from_private_key = private_key.public_key()
# From the public components -
public_numbers = EllipticCurvePublicNumbers(x, y, ECC_CURVE)
public_key_from_public_numbers = public_numbers.public_key(backend=BACK_END)
# Make sure the two are identical.
assert(public_key_from_private_key.public_numbers() == public_key_from_public_numbers.public_numbers())

# Check signature.
signature_valid = True
try:
    public_key_from_public_numbers.verify(signature_der, to_be_signed, ec.ECDSA(hashes.SHA256()))
except InvalidSignature:
    signature_valid = False

if signature_valid:
    print("The signature is valid!")
else:
    print("The signature is NOT valid.")
