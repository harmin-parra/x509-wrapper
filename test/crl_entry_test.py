from wrapper.x509 import CRL
from cryptography import x509
import os
import pytest

#
# Fixtures for tests
#
_crl = None

@pytest.fixture
def crl():
    global _crl
    if _crl is None:
        _crl = CRL.load_pem_file(f"test{os.sep}resources{os.sep}pem.crl")
    return _crl

#
# Dumpers
#
def test_reason_inv_date_absent_absent(crl):
    serial = "43F979C30F6C78AC3AB7A75963B2ACB36ACE388C"
    entry = crl.get_entry(serial)
    assert isinstance(entry._obj, x509.RevokedCertificate)
    print(entry.dump())

def test_reason_absent(crl):
    serial = "034453ECC0EF36EC0551495FC69B29109CF9CE5E"
    entry = crl.get_entry(serial)
    assert isinstance(entry._obj, x509.RevokedCertificate)
    print(entry.dump())

def test_inv_date_absent(crl):
    serial = "72F44D160CE137D743449DE29DDD99B6AC58CE77"
    entry = crl.get_entry(serial)
    assert isinstance(entry._obj, x509.RevokedCertificate)
    print(entry.dump())

def test_all(crl):
    serial = "3052EDA4E78C8A15FDA68AE9A64E8EABC3D27B6D"
    entry = crl.get_entry(serial)
    assert isinstance(entry._obj, x509.RevokedCertificate)
    print(entry.dump())
