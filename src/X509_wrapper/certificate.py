import datetime
import subprocess
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from X509_wrapper import BASE, get_general_names, decode_asn1_bytes


class _X509(BASE):

    def __init__(self):
        super().__init__()

    #
    # GETTERS
    #

    def get_serial_number(self, fmt='HEX'):
        assert fmt == 'HEX' or fmt == 'INT', 'invalid parameter value: ' + fmt
        if fmt == 'INT':
            return self._obj.serial_number
        else:
            # return hex(self._obj.serial_number)[2:]
            return format(self._obj.serial_number, 'X').rjust(40, '0')

    def get_ian_list(self):
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME)
            return get_general_names(ext)
        except x509.extensions.ExtensionNotFound:
            return None

    def get_sid(self):
        for ext in self._obj.extensions:
            if ext.value.oid.dotted_string == "1.3.6.1.4.1.311.25.2":
                tag, val = decode_asn1_bytes(ext.value.value)
                tag ,val = decode_asn1_bytes(val)
                return val
        return None

    def get_ocsp_nocheck(self):
        for ext in self._obj.extensions:
            if ext.value.oid.dotted_string == "1.3.6.1.5.5.7.48.1.5":
                return ext.critical
        return None

    def has_expired(self):
        return self._obj.not_valid_after <= datetime.datetime.now()

    def get_not_valid_after(self):
        return self._obj.not_valid_after

    def get_not_valid_befeore(self):
        return self._obj._not_valid_before

    def get_crl_dp(self):
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            for e in ext:
                result.append(str(e.full_name[0].value))
        except x509.extensions.ExtensionNotFound:
            return None
        return result

    def get_delta_dp(self):
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL).value
            for e in ext:
                result.append(e.full_name[0].value)
        except x509.extensions.ExtensionNotFound:
            return None
        return result

    def get_authority_info_access(self):
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for e in ext:
                result.append(e.access_method._name + ": " + e.access_location.value)
        except x509.extensions.ExtensionNotFound:
            return None
        return result

    def get_key_usage(self):
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
        if fmt == "TEXT":
            file = "tmp/file.pem"
            self.save(file, "PEM")
            p = subprocess.run(["openssl", "x509", "-text", "-noout", "-in", file], capture_output=True)
            p.check_returncode()
            return p.stdout.decode() 
        else:
            return super().dump(fmt)


def load_pem_file(filepath):
    obj = _X509()
    obj.load_from_file(filepath, x509.load_pem_x509_certificate)
    return obj


def load_der_file(filepath):
    obj = _X509()
    obj.load_from_file(filepath, x509.load_der_x509_certificate)
    return obj


def load_base64(b64):
    b64 = "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----"
    obj = _X509()
    obj.load_from_base64(b64, x509.load_pem_x509_certificate)
    return obj
