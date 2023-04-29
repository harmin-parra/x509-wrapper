import datetime, subprocess
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from X509_wrapper import BASE, get_general_names


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
            return []

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
            pass
        return result

    def get_delta_dp(self):
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL).value
            for e in ext:
                result.append(e.full_name[0].value)
        except x509.extensions.ExtensionNotFound:
            pass
        return result

    def get_authority_info_access(self):
        result = []
        try:
            ext = self._obj.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for e in ext:
                result.append(e.access_method._name + ": " + e.access_location.value)
        except x509.extensions.ExtensionNotFound:
            pass
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
            pass
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
