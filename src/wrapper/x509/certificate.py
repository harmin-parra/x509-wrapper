import datetime
import platform
import subprocess
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from . import BASE, get_general_names


class Certificate(BASE):

    #
    # Loaders
    #
    @classmethod
    def load_pem_file(cls, filepath):
        """ Loads a certificate from a PEM format file.
        Args:
            filepath (str): File path of the file to load.
        Returns:
            The Certificate object.
        """
        obj = cls()
        obj.load_from_file(filepath, x509.load_pem_x509_certificate)
        return obj

    @classmethod
    def load_der_file(cls, filepath):
        """ Loads a certificate from a DER format file. 
        Args:
            filepath (str): File path of the file to load.
        Returns:
            The Certificate object.
        """
        obj = cls()
        obj.load_from_file(filepath, x509.load_der_x509_certificate)
        return obj

    @classmethod
    def load_base64(cls, b64):
        """ Loads a certificate from a Base64 string.
        Args:
            b64 (str): The base64 string to load.
        Returns:
            The Certificate object.
        """
        b64 = "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----"
        obj = cls()
        obj.load_from_base64(b64, x509.load_pem_x509_certificate)
        return obj

    #
    # GETTERS
    #
    def get_serial_number(self, fmt='HEX'):
        """ Returns the serial number.
        Args:
            fmt (str, optional): The format on which the serial number should be returned.
                Possible values: 'HEX' for hexadecimal and 'INT' for bit integer.
        """
        if fmt not in('HEX', 'INT'):
            raise ValueError(f"invalid parameter value: '{fmt}'. Expected value: 'HEX' or 'INT'")
        if fmt == 'INT':
            return self._obj.serial_number
        else:
            # return hex(self._obj.serial_number)[2:]
            return format(self._obj.serial_number, 'X').rjust(40, '0')

    def get_ian(self):
        """ Returns the issuer alternative name extension value as a list of string. """
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME)
            return get_general_names(ext)
        except x509.extensions.ExtensionNotFound:
            return None

    def get_sid(self):
        """ Returns the Microsoft SID extension value. """
        for ext in self._obj.extensions:
            if ext.value.oid.dotted_string == "1.3.6.1.4.1.311.25.2":
                import asn1
                decoder = asn1.Decoder()
                decoder.start(ext.value.value)
                tag, val = decoder.read()
                decoder.start(val)
                tag, val = decoder.read()
                decoder.start(val)
                tag, val = decoder.read()
                decoder.peek()
                decoder.enter()
                tag, val = decoder.read()
                return val.decode()
        return None

    def get_ocsp_nocheck(self):
        """ Returns the OSCP no-check extension value. """
        for ext in self._obj.extensions:
            if ext.value.oid.dotted_string == "1.3.6.1.5.5.7.48.1.5":
                return ext.critical
        return None

    def has_expired(self):
        """ Informs whether the certificate has expired. """
        return self._obj.not_valid_after <= datetime.datetime.now()

    def get_not_valid_after(self):
        """ Returns the Not Valid After extension value as datetime.datetime. """
        return self._obj.not_valid_after

    def get_not_valid_before(self):
        """ Returns the Not Valid Before extension value as datetime.datetime. """
        return self._obj.not_valid_before

    def get_crl_dp(self):
        """ Returns the CRL distribution point extension value as a list of strings. """
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            for e in ext:
                result.append(str(e.full_name[0].value))
        except x509.extensions.ExtensionNotFound:
            return None
        return result

    def get_delta_dp(self):
        """ Returns the Delta CRL distribution point extension value as a list of strings. """
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL).value
            for e in ext:
                result.append(e.full_name[0].value)
        except x509.extensions.ExtensionNotFound:
            return None
        return result

    def get_authority_info_access(self):
        """ Returns the Authority Information Access extension value as a list of strings. """
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for e in ext:
                result.append(e.access_method._name + ": " + e.access_location.value)
        except x509.extensions.ExtensionNotFound:
            return None
        return result

    def get_key_usage(self):
        """ Returns the Key Usage extension value as a dictionary. """
        result = {}
        try:
            result['critical'] = self._obj.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).critical
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            result['digital_signature'] = ext.digital_signature
            result['content_commitment'] = ext.content_commitment
            result['key_encipherment'] = ext.key_encipherment
            result['data_encipherment'] = ext.data_encipherment
            result['key_agreement'] = ext.key_agreement
            result['certificate_sign'] = ext.key_cert_sign
            result['crl_sign'] = ext.crl_sign
            if not ext.key_agreement:
                result['encipher_only'] = False
                result['decipher_only'] = False
            else:
                result['encipher_only'] = ext.encipher_only
                result['decipher_only'] = ext.decipher_only                
        except x509.extensions.ExtensionNotFound:
            return None
        return result

    def get_ext_key_usage(self):
        """ Returns the Extended Key Usage extension value as a dictionary. """
        result = {}
        try:
            result['critical'] = self._obj.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).critical
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            values = []
            for e in ext:
                values.append(e.dotted_string)
            result['value'] = values
        except x509.extensions.ExtensionNotFound:
            return None
        return result

    def get_policies(self):
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
            for e in ext:
                '''
                if type(e._policy_qualifiers) == list:
                    if type(e._policy_qualifiers[0]) == cryptography.x509.extensions.UserNotice:
                        print(e._policy_qualifiers[0].explicit_text)
                        print(e._policy_qualifiers[0].notice_reference.organization)
                        print(e._policy_qualifiers[0].notice_reference.notice_numbers)
                '''
                oid = e._policy_identifier.dotted_string
                value = "OID: " + oid
                if e._policy_qualifiers is not None:
                    value += " - " + str(e._policy_qualifiers)
                result.append(value)
        except x509.extensions.ExtensionNotFound:
            return None
        return result

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
                # p = subprocess.Popen(["openssl", "x509", "-text", "-noout"], stdin = subprocess.PIPE, stdout = subprocess.PIPE)
                # p.communicate(input=bytes(pem, encoding='utf-8'))
                p = subprocess.run(["openssl", "x509", "-text", "-noout"], \
                                   input = pem, capture_output = True, \
                                   text = True, check = False)
                if p.returncode != 0:
                    return p.stdout + '\n' + p.stderr
                else:
                    return p.stdout
        else:
            return super().dump(fmt = fmt)
