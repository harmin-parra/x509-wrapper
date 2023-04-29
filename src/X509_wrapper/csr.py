import asn1
import ipaddress
import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat._oid import ObjectIdentifier
from X509_wrapper import BASE


def encode_to_der(content, typ=asn1.Numbers.UTF8String):
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(content, typ)
    return encoder.output()

def generate(file_csr='file.csr', file_key='file.key', file_format='PEM', \
             key_type='RSA', key_size=3072, key_curve=ec.SECP256R1, \
             CN=None, OU=None, O=None, C=None, \
             DNS=None, IP=None, URI=None, RegID=None, Email=None, UPN=None, SID=None):
    assert file_format in ('PEM', 'DER')
    assert key_type in ('RSA', 'ECDSA')
    assert key_size in (1024, 2048, 3072, 4096)

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
