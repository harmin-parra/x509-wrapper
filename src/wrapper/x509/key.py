import base64, hashlib, subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from . import BASE


class KEY(BASE):

    def __init__(self, obj=None):
        super().__init__(obj)

    #
    # GETTERS
    #
    def get_type(self):
        if isinstance(self._obj, RSAPublicKey) or isinstance(self._obj, RSAPrivateKey):
            return "RSA"
        elif isinstance(self._obj, EllipticCurvePublicKey) or isinstance(self._obj, EllipticCurvePrivateKey):
            return "ECDSA"
        else:
            return "Other"

    def get_size(self):
        return self._obj.key_size

    def get_curve(self):
        if self.get_type() == "ECDSA":
            return self._obj.curve.name
        else:
            return None

    def get_digest(self):
        return hashlib.sha256(base64.b64decode(self.dump('BASE64'))).hexdigest()

    #
    # OPERATORS OVERLOADING
    #
    def __eq__(self, other):
        super().__eq__(other)

    #
    # DUMP
    #
    def dump(self, fmt='TEXT'):
        if fmt == "BASE64":
            lines = self.dump("PEM").splitlines()
            del lines[0]
            del lines[-1]
            return ''.join(lines)

        if fmt == "TEXT":
            file = "tmp/file.pem"
            f = open(file, "w")
            f.write(self.dump("PEM"))
            f.close()
            if isinstance(self._obj, RSAPublicKey):
                p = subprocess.run(["openssl", "rsa", "-text", "-noout", "-pubin", "-in", file], capture_output=True)
                p.check_returncode()
                return p.stdout.decode()
            if isinstance(self._obj, RSAPrivateKey):
                p = subprocess.run(["openssl", "rsa", "-text", "-noout", "-in", file], capture_output=True)
                p.check_returncode()
                return p.stdout.decode()
            if isinstance(self._obj, EllipticCurvePublicKey):
                p = subprocess.run(["openssl", "ec", "-text", "-noout", "-pubin", "-in", file], capture_output=True)
                p.check_returncode()
                return p.stdout.decode()
            if isinstance(self._obj, EllipticCurvePrivateKey):
                p = subprocess.run(["openssl", "ec", "-text", "-noout", "-in", file], capture_output=True)
                p.check_returncode()
                return p.stdout.decode()

        if isinstance(self._obj, RSAPublicKey) or isinstance(self._obj, EllipticCurvePublicKey):
            if fmt == "PEM":
                return self._obj.public_bytes(Encoding.PEM, \
                    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            elif fmt == "DER":
                return self._obj.public_bytes(Encoding.DER, \
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
        elif isinstance(self._obj, RSAPrivateKey) or isinstance(self._obj, EllipticCurvePrivateKey):
            if fmt == "PEM":
                return self._obj.private_bytes(Encoding.PEM, \
                    format=serialization.PrivateFormat.TraditionalOpenSSL, \
                    encryption_algorithm=serialization.NoEncryption()).decode()
            elif fmt == "DER":
                return self._obj.private_bytes(Encoding.DER, \
                    format=serialization.PrivateFormat.TraditionalOpenSSL, \
                    encryption_algorithm=serialization.NoEncryption())
        else:
            return "Unsupported key_priv type"

def load_public_key_pem_file(filepath):
    obj = KEY()
    obj.load_from_file(filepath, serialization.load_pem_public_key)
    return obj

def load_public_key_der_file(filepath):
    obj = KEY()
    obj.load_from_file(filepath, serialization.load_der_public_key)
    return obj    
    
def load_private_key_pem_file(filepath, passphrase=None):
    obj = KEY()
    obj.load_from_file(filepath, serialization.load_pem_private_key, passphrase)
    return obj
    
def load_private_key_der_file(filepath, passphrase=None):
    obj = KEY()
    obj.load_from_file(filepath, serialization.load_der_private_key, passphrase)
    return obj

def load_public_key_base64(b64):
    b64 = "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----"
    obj = KEY()
    obj.load_from_base64(b64, serialization.load_pem_public_key)
    return obj

def load_private_key_base64(b64):
    b64 = b64 = "-----BEGIN RSA PRIVATE KEY-----\n" + b64 + "\n-----END RSA PRIVATE KEY-----"
    obj = KEY()
    obj.load_from_base64(b64, serialization.load_pem_private_key)
    return obj
