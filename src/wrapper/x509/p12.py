import base64
from . import KEY
from . import Certificate
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization


class P12():

    def __init__(self):
        self._obj = None

    #
    # LOADERS
    #

    # Loads a PKCS12 file
    # filepath: The file path of the PKCS12 to load
    @classmethod
    def load_from_file(cls, filepath, passphrase=None):
        p12 = cls()
        if passphrase is not None:
            passphrase = passphrase.encode()
        try:
            f = open(filepath, 'rb')
            content = f.read()
            f.close()
            p12._obj = pkcs12.load_pkcs12(content, passphrase)
            return p12
        except ValueError as err:
            print("Invalid PKCS12 object:\n" + format(err) + "\n")
            raise err
        except OSError as err:
            print('Could not open file "' + filepath + '"\n' + format(err))
            raise err

    # Loads a PKCS12 file
    # b64: The base64 of the PKCS12 to load
    @classmethod
    def load_from_base64(cls, b64, passphrase=None):
        p12 = cls()
        if passphrase is not None:
            passphrase = passphrase.encode()
        p12._obj = pkcs12.load_pkcs12(base64.b64decode(b64), passphrase)
        return p12

    #
    # GETTERS
    #
    def get_cert(self):
        return Certificate(self._obj.cert.certificate)

    def get_key(self):
        return KEY(self._obj.key)

    #
    # PERSISTANCE
    #
    @staticmethod
    def save(cert, key, filepath, passphrase=None):
        if passphrase:
            algorithm = serialization.BestAvailableEncryption(passphrase.encode())
        else:
            algorithm = serialization.NoEncryption()
        buffer = pkcs12.serialize_key_and_certificates("1".encode(), key._obj, cert._obj, None, algorithm)
        f = open(filepath, "wb")
        f.write(buffer)
        f.close()

    #
    # DUMP
    #

    # Return a representation of the PKCS12
    # fmt: The format of the PKCS12 representation. Values: TEXT or BASE64.
    def dump(self, fmt='BASE64'):
        if fmt not in ('DER', 'TEXT', 'BASE64'):
            raise ValueError(f"invalid parameter value: '{fmt}'. Expected value: 'DER', 'TEXT' or 'BASE64'")
        if fmt == "TEXT":
            return self.get_cert().dump('TEXT') + '\n' + self.get_key().dump('TEXT')
        elif fmt == "BASE64":  # fmt == "BASE64"
            return base64.b64encode(pkcs12.serialize_key_and_certificates(None, self._obj.key, self._obj.cert.certificate, None, serialization.NoEncryption())).decode()
        else: # fmt == 'DER'
            pem = self.dump(fmt = 'BASE64')
            return base64.b64decode(pem.encode())
            