from wrapper.x509 import CRL
import cryptography.x509
import datetime
import os
import pytest

#
# Test loaders
#
def test_load_pem_file():
    delta = CRL.load_pem_file(f"test{os.sep}resources{os.sep}pem.delta.crl")
    assert isinstance(delta._obj, cryptography.x509.CertificateRevocationList)

def test_load_der_file():
    delta = CRL.load_der_file(f"test{os.sep}resources{os.sep}der.delta.crl")
    assert isinstance(delta._obj, cryptography.x509.CertificateRevocationList)

def test_load_base64():
    b64 = "MIIEpTCCAw0CAQEwDQYJKoZIhvcNAQELBQAwJzEQMA4GA1UECgwHQ29tcGFueTETMBEGA1UEAwwKRXhhbXBsZSBDQRcNMjMwNTAyMDkwMDE1WhcNMzMwNDI5MDkwMDE1WjCCAmEwJQIUQ/l5ww9seKw6t6dZY7Kss2rOOIwXDTIzMDQzMDA4MjQxN1owQQIUA0RT7MDvNuwFUUlfxpspEJz5zl4XDTIzMDQzMDA4MjQyOFowGjAYBgNVHRgEERgPMjAyMzA0MzAwODAwMjhaMDMCFBzgd/FxvZG16xXGXUT7/7fd9KQiFw0yMzA0MzAwODI0NDFaMAwwCgYDVR0VBAMKAQYwMwIUcvRNFgzhN9dDRJ3ind2ZtqxYzncXDTIzMDQzMDA4MjQ1MVowDDAKBgNVHRUEAwoBATBNAhQwUu2k54yKFf2miummTo6rw9J7bRcNMjMwNDMwMDgyNTA1WjAmMAoGA1UdFQQDCgECMBgGA1UdGAQRGA8yMDIzMDQzMDA4MDAwNVowMwIUAi//abIqHxscsBp68Cgo+uHIJGkXDTIzMDQzMDA4MjUxN1owDDAKBgNVHRUEAwoBAzAzAhRN0eNUIc/soll8JXkrCKef2GplIxcNMjMwNDMwMDgyNTMwWjAMMAoGA1UdFQQDCgEDMDMCFDYuxhm9bWrokVb6XnUTgJ6zet9bFw0yMzA0MzAwODI1NTVaMAwwCgYDVR0VBAMKAQQwMwIUcayEFfIQXgMbSfQD7X/m9sUrBk8XDTIzMDQzMDA4MjYwOFowDDAKBgNVHRUEAwoBBTAzAhQMG+wN6r2vCYEiTimaiCYOZnEedxcNMjMwNDMwMDgyNjE5WjAMMAoGA1UdFQQDCgEJMDMCFGUuwCmqM9lz+HkgyChnwr6EiG2WFw0yMzA0MzAwODI2MzBaMAwwCgYDVR0VBAMKAQqgTTBLMAoGA1UdFAQDAgEDMB8GA1UdIwQYMBaAFMb9+MMM9yQiTGf1RJ87WZo3U+9WMBwGCSsGAQQBgjcVBAQPFw0yMzA1MTIwOTAwMTVaMA0GCSqGSIb3DQEBCwUAA4IBgQCTB6iHd3Jdn2/AjKQysKQxneQEopJxRqEeeztYKi2mlyxiQBUa5t94c9DmJV8D5BrmqAnVs3Lr89iEwIyIoiNIqT+iZ6DJh7ejteFXkwzw0NKPHWUNfgkcuiVajiSznUXTKQSZeuzDwasS6Z2p/sp6j1o3/x77tazoxucW65syNLXD9X51QXOIvQRgPptVAyl4UByZNb5FYxUydl0kNngsMbvTn20adRpcVCMYeCIrMvPhipVYFbntyxC8OE/9VfLZggOQV/o08ysrrpnJhQDZCSh3NkkDiDprNCuRi0dx2mRAs5/WxBi2U4RO5ehbnr9ASwAphNverqYb68s5bbHlsskuoJ7E7OGsPBWimTQehyPHX/ohJZ+FrATPKeIHxI6cZqqZ188KSJuD0S48p2HDyOGpj0oKHBIdEQR/fsdMrHDk5oVI+OBu+EkRzEUdtYINBWcozXlV3xZ73liIft5yhCWQD9UAJeS4cpgyYeKxN8WQmYPbMiCTUsQ+Q/9qc3E="
    delta = CRL.load_base64(b64)
    assert isinstance(delta._obj, cryptography.x509.CertificateRevocationList)

#
# Fixtures for getter tests
#
_delta1 = None

@pytest.fixture
def delta1():
    global _delta1
    if _delta1 is None:
        _delta1 = CRL.load_pem_file(f"test{os.sep}resources{os.sep}pem.delta.crl")
    return _delta1

#
# Test getters
#
def test_issuer_dn(delta1):
    assert delta1.get_issuer_dn() == "CN=Example CA,O=Company"

def test_aki(delta1):
    assert delta1.get_aki() is None

def test_crl_number(delta1):
    assert delta1.get_crl_number() == 3

def test_is_delta(delta1):
    assert delta1.is_delta_crl()

def test_delta_number(delta1):
    assert delta1.get_delta_number() == 2

def test_next_publish(delta1):
    assert delta1.get_next_publish() is None

def test_get_revoked_unspecified(delta1):
    entry = delta1.get_entry("43F979C30F6C78AC3AB7A75963B2ACB36ACE388C")
    assert entry is not None
    assert entry.get_revocation_date() == datetime.datetime(2023, 4, 30, 8, 24, 17)
    assert entry.get_reason() is None
    assert entry.get_invalidity_date() is None

def test_get_revoked_unspecified_invalidity_date(delta1):
    entry = delta1.get_entry("034453ECC0EF36EC0551495FC69B29109CF9CE5E")
    assert entry is not None
    assert entry.get_revocation_date() == datetime.datetime(2023, 4, 30, 8, 24, 28)
    assert entry.get_reason() is None
    assert entry.get_invalidity_date() == datetime.datetime(2023, 4, 30, 8, 0, 28)

def test_get_revoked_key_compromise(delta1):
    entry = delta1.get_entry("72F44D160CE137D743449DE29DDD99B6AC58CE77")
    assert entry is not None
    assert entry.get_revocation_date() == datetime.datetime(2023, 4, 30, 8, 24, 51)
    assert entry.get_reason() == "keyCompromise"
    assert entry.get_invalidity_date() is None

def test_get_revoked_ca_compromise(delta1):
    entry = delta1.get_entry("3052EDA4E78C8A15FDA68AE9A64E8EABC3D27B6D")
    assert entry is not None
    assert entry.get_revocation_date() == datetime.datetime(2023, 4, 30, 8, 25, 5)
    assert entry.get_reason() == "cACompromise"
    assert entry.get_invalidity_date() == datetime.datetime(2023, 4, 30, 8, 0, 5)

def test_not_revoked(delta1):
    serial = "3052EDA4E78C8A15FDA68AE9A64E8EABC3D27B6A"
    entry = delta1.get_entry(serial)
    assert entry is None

#
# Dumpers
#
def test_dump(delta1):
    print(delta1.dump("DER"))
    print(delta1.dump("BASE64"))
    print(delta1.dump("PEM"))
    print(delta1.dump("TEXT"))
