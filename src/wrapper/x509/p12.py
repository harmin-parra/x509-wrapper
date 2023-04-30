import base64
from x509 import key
from x509 import certificate
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
    def load_from_file(self, filepath, passphrase=None):
        if passphrase is not None:
            passphrase = passphrase.encode()
        try:
            f = open(filepath, 'rb')
            content = f.read()
            f.close()
            self._obj = pkcs12.load_pkcs12(content, passphrase)
        except ValueError as err:
            print("Invalid PKCS12 object:\n" + format(err) + "\n")
            raise err
        except OSError as err:
            print('Could not open file "' + filepath + '"\n' + format(err))
            raise err

    # Loads a PKCS12 file
    # p12: The base64 of the PKCS12 to load
    def load_from_base64(self, b64, passphrase=None):
        if passphrase is not None:
            passphrase = passphrase.encode()
        self._obj = pkcs12.load_pkcs12(base64.b64decode(b64), passphrase)

    #
    # GETTERS
    #
    def get_cert(self):
        return certificate(self._obj.cert.certificate)

    def get_key(self):
        return key(self._obj.key)

    #
    # PERSISTANCE
    #

    def save(self, filepath, passphrase=None):
        if passphrase:
            algorithm = serialization.BestAvailableEncryption(passphrase.encode())
        else:
            algorithm = serialization.NoEncryption()
        buffer = pkcs12.serialize_key_and_certificates(None, self._obj.key, self._obj.cert.certificate, None, algorithm)
        f = open(filepath, "wb")
        f.write(buffer)
        f.close()

    #
    # DUMP
    #

    # Return a representation of the PKCS12
    # fmt: The format of the PKCS12 representation. Values: TEXT or BASE64.
    def dump(self, fmt='BASE64'):
        assert fmt in ('TEXT', 'BASE64'), 'invalid parameter value: ' + fmt
        if fmt == "TEXT":
            return self.get_cert().dump('TEXT') + '\n' + self.get_key().dump('TEXT')
        else:  # fmt == "BASE64"
            return base64.b64encode(pkcs12.serialize_key_and_certificates(None, self._obj.key, self._obj.cert.certificate, None, serialization.NoEncryption())).decode()
