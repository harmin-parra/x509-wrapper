import base64
import hashlib
import platform
import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from . import BASE


class KEY(BASE):

    #
    # Loaders
    #
    @classmethod
    def load_public_key_pem_file(cls, filepath):
        """ Loads a public key from a PEM format file.
        Args:
            filepath (str): File path of the file to load.
        Returns:
            The public key object.
        """
        obj = cls()
        obj.load_from_file(filepath, serialization.load_pem_public_key)
        return obj

    @classmethod
    def load_public_key_der_file(cls, filepath):
        """ Loads a public key from a DER format file.
        Args:
            filepath (str): File path of the file to load.
        Returns:
            The public key object.
        """
        obj = cls()
        obj.load_from_file(filepath, serialization.load_der_public_key)
        return obj

    @classmethod
    def load_public_key_base64(cls, b64):
        """ Loads a public key from a Base64 string.
        Args:
            b64 (str): The base64 string to load.
        Returns:
            The public key object.
        """
        b64 = "-----BEGIN PUBLIC KEY-----" + '\n' + \
              b64 + '\n' + \
              "-----END PUBLIC KEY-----"
        obj = cls()
        obj.load_from_base64(b64, serialization.load_pem_public_key)
        return obj

    @classmethod
    def load_private_key_pem_file(cls, filepath, passphrase=None):
        """ Loads a private key from a PEM format file.
        Args:
            filepath (str): File path of the file to load.
        Returns:
            The private key object.
        """
        obj = cls()
        obj.load_from_file(filepath, serialization.load_pem_private_key, passphrase)
        return obj

    @classmethod
    def load_private_key_der_file(cls, filepath, passphrase=None):
        """ Loads a private key from a DER format file.
        Args:
            filepath (str): File path of the file to load.
        Returns:
            The private key object.
        """
        obj = cls()
        obj.load_from_file(filepath, serialization.load_der_private_key, passphrase)
        return obj

    @classmethod
    def load_private_key_base64(cls, b64):
        """ Loads a private key from a Base64 string.
        Args:
            b64 (str): The base64 string to load.
        Returns:
            The private key object.
        """
        b64 = b64 = "-----BEGIN RSA PRIVATE KEY-----" + '\n' + \
                    b64 + '\n' + \
                    "-----END RSA PRIVATE KEY-----"
        obj = cls()
        obj.load_from_base64(b64, serialization.load_pem_private_key)
        return obj

    #
    # GETTERS
    #
    def get_type(self):
        """ Returns the key type as string. ""
        Returns:
            The key type. Possible values: 'RSA', 'ECDSA' and 'Other'
        """
        if isinstance(self._obj, RSAPublicKey) or isinstance(self._obj, RSAPrivateKey):
            return "RSA"
        elif isinstance(self._obj, EllipticCurvePublicKey) or isinstance(self._obj, EllipticCurvePrivateKey):
            return "ECDSA"
        else:
            return "Other"

    def get_size(self):
        """ Returns the key size as int. ""
        Returns:
            The key size.
        """
        return self._obj.key_size

    def get_curve(self):
        """ Returns the key curve as string. ""
        Returns:
            The key curve.
        """
        if self.get_type() == "ECDSA":
            return self._obj.curve.name
        else:
            return None

    def get_digest(self):
        return hashlib.sha256(base64.b64decode(self.dump('BASE64'))).hexdigest()

    #
    # DUMP
    #
    def dump(self, fmt='TEXT'):
        """ Returns a string or bytes representation of the object.
        'TEXT' format is not supported on Windows.
        Args:
            fmt (str, optional): The format of the object representation. Accepted values: PEM, DER, TEXT or BASE64.
        Returns:
            The string representation of the object if fmt = 'PEM', 'TEXT' or 'BASE64'.
            The bytes representation of the object if fmt = 'DER'.
        """
        if fmt not in ('PEM', 'DER', 'TEXT', 'BASE64'):
            raise ValueError(f"invalid parameter value: '{fmt}'. Expected value: 'PEM', 'DER', 'TEXT' or 'BASE64'")
        if self.get_type() == "Other":
            return "Unsupported key type"

        if fmt == "BASE64":
            lines = self.dump(fmt="PEM").splitlines()
            del lines[0]
            del lines[-1]
            return ''.join(lines)

        if fmt == 'PEM':
            if isinstance(self._obj, RSAPublicKey) or isinstance(self._obj, EllipticCurvePublicKey):
                return self._obj.public_bytes(Encoding.PEM,
                                              format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            elif isinstance(self._obj, RSAPrivateKey) or isinstance(self._obj, EllipticCurvePrivateKey):
                return self._obj.private_bytes(Encoding.PEM,
                                               format=serialization.PrivateFormat.TraditionalOpenSSL,
                                               encryption_algorithm=serialization.NoEncryption()).decode()

        if fmt == 'DER':
            if isinstance(self._obj, RSAPublicKey) or isinstance(self._obj, EllipticCurvePublicKey):
                return self._obj.public_bytes(Encoding.DER,
                                              format=serialization.PublicFormat.SubjectPublicKeyInfo)
            elif isinstance(self._obj, RSAPrivateKey) or isinstance(self._obj, EllipticCurvePrivateKey):
                return self._obj.private_bytes(Encoding.DER,
                                               format=serialization.PrivateFormat.TraditionalOpenSSL,
                                               encryption_algorithm=serialization.NoEncryption())

        if fmt == "TEXT":
            if platform.system() == "Windows":
                return "Dump in TEXT format not supported on Windows"
            else:
                pem = self.dump(fmt='PEM')
                p = None
                if isinstance(self._obj, RSAPublicKey):
                    p = subprocess.run(["openssl", "pkey", "-text", "-noout", "-pubin"],
                                       input=pem, capture_output=True,
                                       text=True, check=False)
                elif isinstance(self._obj, RSAPrivateKey):
                    p = subprocess.run(["openssl", "rsa", "-text", "-noout"],
                                       input=pem, capture_output=True,
                                       text=True, check=False)
                elif isinstance(self._obj, EllipticCurvePublicKey):
                    p = subprocess.run(["openssl", "ec", "-text", "-noout", "-pubin"],
                                       input=pem, capture_output=True,
                                       text=True, check=False)
                elif isinstance(self._obj, EllipticCurvePrivateKey):
                    p = subprocess.run(["openssl", "ec", "-text", "-noout"],
                                       input=pem, capture_output=True,
                                       text=True, check=False)
                if p.returncode != 0:
                    return p.stdout + '\n' + p.stderr
                else:
                    return p.stdout
