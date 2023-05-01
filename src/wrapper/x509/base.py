import asn1
from abc import (
    ABC,
    abstractmethod,
)
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat


def decode_asn1_bytes(value):
    decoder = asn1.Decoder()
    decoder.start(value)
    tag, value = decoder.read()
    return tag, value

def get_general_names(names):
    """ Extract the SAN extensions values of crypto objects X509 and CSR.
    Parameters:
        name (list(cryptography.X509.Extension)): The SAN extensions.
    Returns:
        list(str): The SAN extensions values in string format.
    Example:
        ['DNS:www.example.com', 'IP:127.0.0.1',
        'URI:http://www.example.com', 'Email:email@example.com',
        'RegID:1.3.6.1.4.1.343', 'DirName:CN=machine,O=Company,DC=LDAP',
        "Other:('1.3.6.1.4.1.311.20.2.3', 'upn@example.com')"]
    """
    result = []
    for e in names.value:
        if type(e) == x509.general_name.DNSName:
            result.append("DNS:" + e.value)
        if type(e) == x509.general_name.IPAddress:
            result.append("IP:" + str(e.value))
        if type(e) == x509.general_name.UniformResourceIdentifier:
            result.append("URI:" + e.value)
        if type(e) == x509.general_name.RFC822Name:
            result.append("Email:" + e.value)
        if type(e) == x509.general_name.DirectoryName:
            result.append("DirName:" + e.value.rfc4514_string())
        if type(e) == x509.general_name.RegisteredID:
            result.append("RegID:" + e.value.dotted_string)
        if type(e) == x509.general_name.OtherName:
            tag, value = decode_asn1_bytes(e.value)
            if tag.nr == 4:
                value = value.hex()
            result.append("Other:" + str((e.type_id.dotted_string, value)))
    return result


class BASE(ABC):
    """ Super class for CRL, CSR, KEY and X509 cryptography objects.
    Attributes:
        _obj: The cryptography x509 object (X509, CRL, CSR or KEY).
    """

    #
    # CONSTRUCTORS
    #
    @abstractmethod
    def __init__(self, obj=None):
        self._obj = obj

    #
    # LOADERS
    #
    def load_from_file(self, filepath, load_function, passphrase=None):
        """ Load a crypto object from a DER (binary) encoded string.
        Parameters:
            filepath (str): The file path of the crypto object.
            load_function (function): The function to use to load the crypto object
            passphrase (str, optional): The passphrase of the crypto object.
                                        Relevant only for KEY objects.
        Returns:
            None.
            Initializes _obj private attribute.
        """
        try:
            f = open(filepath, 'rb')
            content = f.read()
            f.close()
            try:
                self._obj = load_function(content, passphrase)
            except ValueError as err:
                print("Invalid " + type(self).__name__ + " object:\n" + format(err) + "\n")
                raise err
        except OSError as err:
            print('Could not open file "' + filepath + '"\n' + format(err))
            raise err

    def load_from_base64(self, b64, load_function, passphrase=None):
        """ Load a cryptography object from a base64 string.
        Parameters:
            b64 (str): The base64 string to load.
            load_function (function): The function to use to load the crypto object
            passphrase (str, optional): The passphrase of the crypto object.
                                        Relevant only for KEY objects.
        Returns:
            None.
            Initializes _obj private attribute.
        """
        self._obj = load_function(b64.encode(), passphrase)

    #
    # GETTERS
    #
    def get_subject_dn(self):
        clazz = type(self).__name__
        if clazz in ("_CRL", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_subject_dn'")
        return self._obj.subject.rfc4514_string()

    def get_issuer_dn(self):
        clazz = type(self).__name__
        if clazz in ("_CSR", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_issuer_dn'")
        return self._obj.issuer.rfc4514_string()

    def get_san(self):
        """ Return the subject alternative name extension value as a list of string. """
        clazz = type(self).__name__
        if clazz in ("_CRL", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_san'")
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return get_general_names(ext)
        except x509.extensions.ExtensionNotFound:
            return None

    def get_aki(self):
        clazz = type(self).__name__
        if clazz in ("_CSR", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_aki'")
        try:
            return self._obj.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier.hex()
        except x509.extensions.ExtensionNotFound:
            return None

    def get_ski(self):
        clazz = type(self).__name__
        if clazz in ("_CRL", "_CSR", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_ski'")
        return self._obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.key_identifier.hex()

    def get_signature_algorithm(self):
        clazz = type(self).__name__
        if clazz in ("_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_signature_algorithm'")
        return self._obj.signature_algorithm_oid._name

    def get_pubkey(self):
        clazz = type(self).__name__
        if clazz in ("_CRL", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_pubkey'")
        from .key import KEY
        return KEY(self._obj.public_key())

    def get_key_type(self):
        clazz = type(self).__name__
        if clazz in ("_CRL", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_key_type'")
        return self.get_pubkey().get_type()

    def get_key_size(self):
        clazz = type(self).__name__
        if clazz in ("_CRL", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_key_size'")
        return self._obj.public_key().key_size

    def get_key_curve(self):
        clazz = type(self).__name__
        if clazz in ("_CRL", "_KEY"):
            raise AttributeError(f"'{clazz}' object has no attribute 'get_key_curve'")
        try:
            return self._obj.public_key().curve.name
        except AttributeError:
            return None

    #
    # OPERATORS OVERLOADING
    #
    def __eq__(self, other):
        if type(other) == type(self):
            if self._obj is None and other._obj is None:
                return True
            if self._obj is None or other._obj is None:
                return False
            return self.dump("BASE64") == other.dump("BASE64")
        return False

    def __ne__(self, other):
        return not self == other

    #
    # PERSISTANCE
    #

    """
    Save the crypto object into a file
    :param: filepath: The file path of the crypto object to save
    :param: fmt: The format of the file. Accepted values: PEM or DER.
    """

    def save(self, filepath, fmt='PEM'):
        assert fmt in ('DER', 'PEM'), 'invalid parameter value: ' + fmt
        encoding = None
        if fmt == 'DER':
            encoding = Encoding.DER
        else:
            encoding = Encoding.PEM
        f = open(filepath, "wb")
        if hasattr(self._obj, 'public_bytes') and callable(self._obj.public_bytes):
            f.write(self._obj.public_bytes(encoding))
        if hasattr(self._obj, 'private_bytes') and callable(self._obj.private_bytes):
            f.write(self._obj.private_bytes(encoding, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
        f.close()

    #
    # DUMP
    #

    """
    Return a string representation of the crypto object
    :param:  fmt: The format of the crypto object representation. Accepted values: TEXT, PEM, DER or BASE64.
    :returns: The specified string representation.
    """

    def dump(self, fmt='TEXT'):
        assert fmt in ('TEXT', 'DER', 'PEM', 'BASE64'), 'invalid parameter value: ' + fmt
        clazz = type(self).__name__
        if clazz == "KEY":
            return NotImplemented
        if fmt == "PEM":
            return self._obj.public_bytes(Encoding.PEM).decode()
        elif fmt == "DER":
            return self._obj.public_bytes(Encoding.DER)
        elif fmt == "BASE64":
            lines = self.dump("PEM").splitlines()
            del lines[0]
            del lines[-1]
            return ''.join(lines)