from wrapper.x509 import P12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12KeyAndCertificates
import os
import pytest


#
# Test loaders
#
def test_load_rsa_file():
    p12 = P12.load_from_file(f"test{os.sep}resources{os.sep}rsa.p12", "1234")
    assert isinstance(p12._obj, PKCS12KeyAndCertificates)

def test_load_ecdsa_file():
    p12 = P12.load_from_file(f"test{os.sep}resources{os.sep}ecdsa.p12", "1234")
    assert isinstance(p12._obj, PKCS12KeyAndCertificates)

def test_load_rsa_base64():
    b64 = "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"
    p12 = P12.load_from_base64(b64, "1234")
    assert isinstance(p12._obj, PKCS12KeyAndCertificates)

def test_load_ecdsa_base64():
    b64 = "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"
    p12 = P12.load_from_base64(b64, "1234")
    assert isinstance(p12._obj, PKCS12KeyAndCertificates)

_rsa = None
_ecdsa = None

@pytest.fixture
def p12_rsa():
    global _rsa
    if _rsa is None:
        _rsa = P12.load_from_file(f"test{os.sep}resources{os.sep}rsa.p12", "1234")
    return _rsa

@pytest.fixture
def p12_ecdsa():
    global _ecdsa
    if _ecdsa is None:
        _ecdsa = P12.load_from_file(f"test{os.sep}resources{os.sep}ecdsa.p12", "1234")
    return _ecdsa

def test_save_rsa(p12_rsa):
    P12.save(p12_rsa.get_cert(), p12_rsa.get_key(), f"test{os.sep}tmp{os.sep}rsa.p12", "test")

def test_save_ecdsa(p12_ecdsa):
    P12.save(p12_ecdsa.get_cert(), p12_ecdsa.get_key(), f"test{os.sep}tmp{os.sep}ecdsa.p12", "test")

def test_dump_rsa(p12_rsa):
    print(p12_rsa.dump("DER"), '\n')
    print(p12_rsa.dump("BASE64"), '\n')
    print(p12_rsa.dump("TEXT"), '\n')

def test_dump_ecdsa(p12_ecdsa):
    print(p12_ecdsa.dump("DER"), '\n')
    print(p12_ecdsa.dump("BASE64"), '\n')
    print(p12_ecdsa.dump("TEXT"), '\n')
