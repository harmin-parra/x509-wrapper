import datetime
import platform
import subprocess
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import CRLEntryExtensionOID
from . import BASE
from . import decode_asn1_bytes


class CRL(BASE):

    #
    # Loaders
    #
    @classmethod
    def load_pem_file(cls, filepath):
        """ Loads a CRL from a PEM format file.
        Args:
            filepath (str): File path of the file to load.
        Returns:
            The CRL object.
        """
        obj = cls()
        obj.load_from_file(filepath, x509.load_pem_x509_crl)
        return obj

    @classmethod
    def load_der_file(cls, filepath):
        """ Loads a CRL from a DER format file.
        Args:
            filepath (str): File path of the file to load.
        Returns:
            The CRL object.
        """
        obj = cls()
        obj.load_from_file(filepath, x509.load_der_x509_crl)
        return obj

    @classmethod
    def load_base64(cls, b64):
        """ Loads a CRL from a Base64 string.
        Args:
            b64 (str): The base64 string to load.
        Returns:
            The CRL object.
        """
        b64 = "-----BEGIN X509 CRL-----\n" + b64 + "\n-----END X509 CRL-----"
        obj = cls()
        obj.load_from_base64(b64, x509.load_pem_x509_crl)
        return obj

    #
    # GETTERS
    #
    # Informs whether the Delta CRL Indicator extension is present
    def is_delta_crl(self):
        try:
            self._obj.extensions.get_extension_for_oid(ExtensionOID.DELTA_CRL_INDICATOR)
            return True
        except x509.extensions.ExtensionNotFound:
            return False

    # Get the Delta CRL number
    # Returns: The Delta CRL number
    def get_delta_number(self):
        try:
            return self._obj.extensions.get_extension_for_oid(ExtensionOID.DELTA_CRL_INDICATOR).value.crl_number
        except x509.extensions.ExtensionNotFound:
            return None

    # Get the CRL number
    # Returns: The CRL number
    def get_crl_number(self):
        return self._obj.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER).value.crl_number

    # Get the Next Publish extension value as datetime.datetime
    def get_next_publish(self):
        for ext in self._obj.extensions:
            if ext.value.oid.dotted_string == "1.3.6.1.4.1.311.21.4":
                dt = decode_asn1_bytes(ext.value.value)[1]
                return datetime.datetime.strptime(dt, "%y%m%d%H%M%SZ")
        return None

    # Get the CRL number
    # Returns: The CRL number
    def get_number(self):
        return self.get_crl_number()

    # Get the CRL revocation entry of a certificate
    # serial: The serial number of the certificate
    # Returns: The CRL entry if present.
    # None if the certificate is not present in the CRL.
    def get_entry(self, serial):
        if not (isinstance(serial, str) or isinstance(serial, int)):
            raise TypeError(f"invalid parameter type: '{type(serial)}'. Expected type: 'int' or 'str'")
        if isinstance(serial, str):
            serial = int(serial, base=16)
        entry = self._obj.get_revoked_certificate_by_serial_number(serial)
        if entry is not None :
            entry = CRL_ENTRY(entry)
        return entry

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
        if fmt not in('PEM', 'DER', 'TEXT', 'BASE64'):
            raise ValueError(f"invalid parameter value: '{fmt}'. Expected value: 'PEM', 'DER', 'TEXT' or 'BASE64'")
        if fmt == "TEXT":
            if platform.system() == "Windows":
                return "Dump in TEXT format not supported on Windows"
            else:
                pem = self.dump(fmt = 'PEM')
                p = subprocess.run(["openssl", "crl", "-text", "-noout"], \
                                   input = pem, capture_output = True, \
                                   text = True, check = False)
                if p.returncode != 0:
                    return p.stdout + '\n' + p.stderr
                else:
                    return p.stdout
        else:
            return super().dump(fmt = fmt)

#
# AUXILIARY CLASS
#

class CRL_ENTRY():

    def __init__(self, obj):
        self._obj = obj

    def get_reason(self):
        try:
            return self._obj.extensions.get_extension_for_oid(CRLEntryExtensionOID.CRL_REASON).value.reason._value_
        except x509.extensions.ExtensionNotFound:
            return None

    def get_revocation_date(self):
        try:
            return self._obj.revocation_date
        except x509.extensions.ExtensionNotFound:
            return None

    def get_invalidity_date(self):
        try:
            return self._obj.extensions.get_extension_for_oid(CRLEntryExtensionOID.INVALIDITY_DATE).value.invalidity_date
        except x509.extensions.ExtensionNotFound:
            return None

    # Return a representation of CRL entry
    # entry: The OpenSSL.crypto.Revoked object
    def dump(self):
        result = "serial = " + hex(self._obj.serial_number)[2:].upper() + '\n' + "revocation date = " + str(self._obj.revocation_date) + '\n'
        try:
            result += "reason = " + self._obj.extensions.get_extension_for_oid(CRLEntryExtensionOID.CRL_REASON).value.reason._value_ + '\n'
        except x509.extensions.ExtensionNotFound:
            pass
        try:
            result += "invalidity date = " + str(self._obj.extensions.get_extension_for_oid(CRLEntryExtensionOID.INVALIDITY_DATE).value.invalidity_date) + '\n'
        except x509.extensions.ExtensionNotFound:
            pass
        return result
