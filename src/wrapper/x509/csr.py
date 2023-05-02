import asn1
import ipaddress
import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat._oid import ObjectIdentifier
from . import BASE


# Auxiliary function for ASN.1 encoding.
def encode_to_der(content, typ=asn1.Numbers.UTF8String):
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(content, typ)
    return encoder.output()

def generate(file_csr='file.csr', file_key='file.key', file_format='PEM', \
             key_type='RSA', key_size=3072, key_curve=ec.SECP256R1, \
             CN=None, OU=None, O=None, C=None, Names=None, \
             DNS=None, IP=None, URI=None, RegID=None, Email=None, UPN=None):
    """ Generate a CSR and private key.
    Parameters:
        file_csr (string): The file path to store the CSR
        file_key (string): The file path to store the private key.
        file_format (string): The format on which the CSR should be generated.
            Possible values: 'PEM' and 'DER'.
        key_type (string): The type of the private key to generate.
            Possible values: 'RSA' and 'ECDSA'.
        key_size (string): The size in bits of the private key to generate.
            Possible values: 1024, 2048, 3072 and 4096
            Only relevant for RSA keys.
        key_curve (cryptography.hazmat.primitives.asymmetric.ec):
            The Elliptic curve of the ECDSA private key to generate.
            Only relevant for ECDSA keys.
        CN (string, optional): The Common Name RDN
        O (string, optional): The Organization RDN
        OU (string, optional): The Organization Unit RDN
        C (string, optional): The Country Code RDN
        Names (Dict[wrapper.x509.RDN, str]: Dictionary of RDNs
            if you need more RDNs apart from CN, O, OU and C
        DNS (list[string], optional): The list of DNS to include in the SAN extension
        IP (list[string], optional): The list of IP addresses to include in the SAN extension
        URI (list[string], optional): The list of URI to include in the SAN extension
        Email (list[string], optional): The list of Emails to include in the SAN extension
        UPN (list[string], optional): The list of UPN emails to include in the SAN extension
        RegID (list[string], optional): The list of Registration IDs to include in the SAN extension
    """
    assert file_format in ('PEM', 'DER')
    assert key_type in ('RSA', 'ECDSA')
    assert key_size in (1024, 2048, 3072, 4096)
    assert key_curve is None or key_curve.__module__ == 'cryptography.hazmat.primitives.asymmetric.ec'

    key = None
    if key_type == 'RSA':
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    else:
        key = ec.generate_private_key(curve=key_curve)
    with open(file_key, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    csr = x509.CertificateSigningRequestBuilder()

    san = []
    if DNS is not None and len(DNS) != 0:
        for i in DNS:
            san.append(x509.DNSName(i))
    if IP is not None and len(IP) != 0:
        for i in IP:
            san.append(x509.IPAddress(ipaddress.IPv4Address(i)))
    if URI is not None and len(URI) != 0:
        for i in URI:
            san.append(x509.UniformResourceIdentifier(i))
    if RegID is not None and len(RegID) != 0:
        for i in RegID:
            san.append(x509.RegisteredID(ObjectIdentifier(i)))
    if Email is not None and len(Email) != 0:
        for i in Email:
            san.append(x509.RFC822Name(i))
    if UPN is not None and len(UPN) != 0:
        for i in UPN:
            san.append(x509.OtherName(ObjectIdentifier('1.3.6.1.4.1.311.20.2.3'), encode_to_der(i)))
    csr = csr.add_extension(x509.SubjectAlternativeName(san), critical=False)
    
    name = []
    if CN is not None:
        name.append(x509.NameAttribute(NameOID.COMMON_NAME, CN))
    if OU is not None:
        name.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU))
    if O is not None:
        name.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, O))
    if C is not None:
        name.append(x509.NameAttribute(NameOID.COUNTRY_NAME, C))
    if Names is not None:
        for rdn in Names:
            name.append(x509.NameAttribute(rdn, Names[rdn]))
    csr = csr.subject_name(x509.Name(name))

    csr = csr.sign(key, hashes.SHA256())

    # Save CSR
    if file_format == 'PEM':
        with open(file_csr, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
    else:
        with open(file_csr, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.DER))


class CSR(BASE):

    def __init__(self):
        super().__init__()

    #
    # DUMP
    #
    def dump(self, fmt='TEXT'):
        if fmt == "TEXT":
            file = "tmp/file.pem"
            self.save(file, "PEM")
            p = subprocess.run(["openssl", "req", "-text", "-noout", "-in", file], capture_output=True)
            p.check_returncode()
            return p.stdout.decode() 
        else:
            return super().dump(fmt)

#
# Loaders
#

def load_pem_file(filepath):
    obj = CSR()
    obj.load_from_file(filepath, x509.load_pem_x509_csr)
    return obj


def load_der_file(filepath):
    obj = CSR()
    obj.load_from_file(filepath, x509.load_der_x509_csr)
    return obj


def load_base64(b64):
    b64 = "-----BEGIN CERTIFICATE REQUEST-----\n" + b64 + "\n-----END CERTIFICATE REQUEST-----"
    obj = CSR()
    obj.load_from_base64(b64, x509.load_pem_x509_csr)
    return obj
