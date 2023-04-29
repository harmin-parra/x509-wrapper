import base64, hashlib, subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from X509_wrapper import BASE


class KEY(BASE):

    def __init__(self, obj=None, key_type="UNKNOWN", key_alg="UNKNOWN"):
        super().__init__(obj)
        self._key_type = key_type
        self._key_alg = key_alg
        if obj is not None:
            self._set_attr()

    def _set_attr(self):
        if self._obj is None:
            return
        if isinstance(self._obj, RSAPrivateKey):
            self._key_alg = "RSA"
            self._key_type = "PRIVATE"
        elif isinstance(self._obj, RSAPublicKey):
            self._key_alg = "RSA"
            self._key_type = "PUBLIC"
        elif isinstance(self._obj, EllipticCurvePrivateKey):
            self._key_alg = "ECDSA"
            self._key_type = "PRIVATE"
        elif isinstance(self._obj, EllipticCurvePublicKey):
            self._key_alg = "ECDSA"
            self._key_type = "PUBLIC"
        else:
            self._key_alg = "UNKNOWN"
            self._key_type = "UNKNOWN"

    #
    # GETTERS
    #
    def get_type(self):
        return self._key_alg

    def get_size(self):
        return self._obj.key_size

    def get_curve(self):
        assert self.get_type() == "ECDSA"
        return self._obj.curve.name

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
    obj._set_attr()
    return obj

def load_public_key_der_file(filepath):
    obj = KEY()
    obj.load_from_file(filepath, serialization.load_der_public_key)
    obj._set_attr()
    return obj    
    
def load_private_key_pem_file(filepath):
    obj = KEY()
    obj.load_from_file(filepath, serialization.load_pem_private_key)
    obj._set_attr()
    return obj
    
def load_private_key_der_file(filepath):
    obj = KEY()
    obj.load_from_file(filepath, serialization.load_der_private_key)
    obj._set_attr()
    return obj

def load_public_key_base64(b64):
    b64 = "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----"
    obj = KEY()
    obj.load_from_base64(b64, serialization.load_pem_public_key)
    obj._set_attr()
    return obj

def load_private_key_base64(b64):
    b64 = b64 = "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----"
    obj = KEY()
    obj.load_from_base64(b64, serialization.load_pem_private_key)
    obj._set_attr()
    return obj
