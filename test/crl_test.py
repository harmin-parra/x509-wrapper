from wrapper.x509 import CRL
import cryptography.x509
import datetime
import pytest

#
# Test loaders
#
def test_load_pem_file():
    crl = CRL.load_pem_file("test/resources/pem.crl")
    assert isinstance(crl._obj, cryptography.x509.CertificateRevocationList)

def test_load_der_file():
    crl = CRL.load_der_file("test/resources/der.crl")
    assert isinstance(crl._obj, cryptography.x509.CertificateRevocationList)

#
# Fixtures for getter tests
#
_csr1 = None
_csr2 = None

@pytest.fixture
def crl1():
    global _csr1
    if _csr1 is None:
        _csr1 = CRL.load_pem_file("test/resources/pem.crl")
    return _csr1

@pytest.fixture
def crl2():
    global _csr2
    if _csr2 is None:
        _csr2 = CRL.load_der_file("test/resources/sha-1.crl")
    return _csr2

#
# Test getters
#
def test_issuer_dn(crl1):
    assert crl1.get_issuer_dn() == "CN=Example CA,O=Company"

def test_aki(crl1):
    assert crl1.get_aki() == "c6fdf8c30cf724224c67f5449f3b599a3753ef56"

def test_crl_number(crl1):
    assert crl1.get_crl_number() == 3

def test_is_delta_absent(crl1):
    assert not crl1.is_delta_crl()

def test_delta_number_absent(crl1):
    assert crl1.get_delta_number() is None

def test_next_publish(crl1):
    assert crl1.get_next_publish() == datetime.datetime(2023, 5, 12, 9, 0, 15)

def test_next_publish_empty(crl2):
    assert crl2.get_next_publish() is None

#
# Dumpers
#
def test_dump(crl1):
    print(crl1.dump("DER"))
    print(crl1.dump("BASE64"))
    print(crl1.dump("PEM"))
