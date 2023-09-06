from cryptography.hazmat.primitives.asymmetric import ec
from wrapper.x509 import CSR, RDN
import cryptography.x509
import pytest


#
# Test loaders
#
def test_load_rsa_der_file():
    csr = CSR.load_der_file("test/resources/rsa.der.csr")
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

def test_load_rsa_pem_file():
    csr = CSR.load_pem_file("test/resources/rsa.pem.csr")
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

def test_load_rsa_base64_string():
    b64 = "MIIEVDCCArwCAQAwIDEQMA4GA1UECgwHQ29tcGFueTEMMAoGA1UEAwwDcnNhMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtdktj74lBI096UamLayC756IXPNkTkgCtG8Vxts7sdFKbWFJxHdfcoMCtEwDQ0Mul7/ENG242srOeOlAlqT9oNAcUIklNi6Sg9JnlFxgsEe/t56sEFM1D44qXciBQybt4jJStU2REnU/LMDuD+aTlxNctDhOKM1Cb3jpblgn0WRqO6vVFcZtZaQFnxRyP+Tdh/7xDmf8+YlP49syp2jF52aEJio5Oks05fSmJyYto7ktJiFxlsH5LUbEIIJjGv8okFa8IpDli1RQWLCIKmpnGHd9MITXK5LWUq0Spl9Gl8gkRtknFsv4OzRt1m5GAHwYuRdD4fnDcy8LyuBxAb2fWSSrzFNUJ9Y+LEjeyDQNKZ/Xx6woOtdZUuLlmRNmuBJGKIsagS9Fs2E+vvitHLe47YR3P3GRntqGf7898Aa0+99l4FRPvltGuahxu6yOMDzJrSpmHh8vXcHBF/vn6ALlh8IrHwKEa8KwVpAmp6zQtLnJqLwZ244LCSY83baWeyuDAgMBAAGgge4wgesGCSqGSIb3DQEJDjGB3TCB2jCB1wYDVR0RBIHPMIHMghVyc2EuZGV2Lm9wZW50cnVzdC5jb22CE3JzYS5kZXYuaWRub21pYy5jb22CCWxvY2FsaG9zdIcEfwAAAYYWaHR0cDovL3d3dy5pZG5vbWljLmNvbYERZW1haWxAaWRub21pYy5jb22gHwYKKwYBBAGCNxQCA6ARDA91cG5AaWRub21pYy5jb22IBysGAQQBglekODA2MRQwEgYKCZImiZPyLGQBGRYETERBUDEQMA4GA1UECgwHQ29tcGFueTEMMAoGA1UEAwwDcnNhMA0GCSqGSIb3DQEBCwUAA4IBgQAesVaJq4HTKyvHxf0J3V0caksDW7irGKg75JfFIrguTQjfklGQK5IJYsTtwSaDZBbQXCgKEfQ4mv8/9lys2Kja1bA4vBI6YdQm1uPGFNA/IAlwx9eeM9wOEPDw0Yfs+dc0//OiSlLTnNxWHgYgVZ5Sm7yyhMIZl0WBaQ5T7zVjQVLYbLhT1fnLQycU0o2pn/rsc+x8d6tOQtCbfz09xKucd+poa/n32/pzfeuiciAevpWrgCY7sjOc3zMgx3ozPVx3xWw8ca6QyuyBMrA867SHdm0P9ID0LpC7w+P+pIY1PV1eu6aMqsLH6A1duTlXiXKZSP6UVgeQ7WiquE+Lkf2LMk6QGbuRGlVHo+fIdgn+3SHwmUMIfsMyuO/D7NMeP3KRDkk6yN6cArCdhcJkBfJtQ51a3OzUt3w8/QejxWSNDjbcMDSLdsk5+/9vOEn7S8ksSfvuZgH/qHnitvIOgTv3aBBqPHFMfEc3Qfy0OzFSpXtIsaM37wqsiU67XSBN6e4="
    csr = CSR.load_base64(b64)
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

def test_load_ecdsa_der_file():
    csr = CSR.load_der_file("test/resources/ecdsa.der.csr")
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

def test_load_ecdsa_pem_file():
    csr = CSR.load_pem_file("test/resources/ecdsa.pem.csr")
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

def test_load_ecdsa_base64_string():
    b64 = "MIHdMIGEAgEAMCIxEDAOBgNVBAoMB0NvbXBhbnkxDjAMBgNVBAMMBWVjZHNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe46AAMAoGCCqGSM49BAMCA0gAMEUCIFp1yT6cTFPfF4bjWonGbuqnKpzqztSzh5eHX2+DRAeEAiEAyzCL4G1Uxlxdo/o3PTYUBCyPUQFCUAe22H1AB/ta1Qg="
    csr = CSR.load_base64(b64)
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

#
# Fixtures for getter tests
#
_rsa = None
_ecdsa = None

@pytest.fixture
def csr_rsa():
    global _rsa
    if _rsa is None:
        _rsa = CSR.load_pem_file("test/resources/rsa.pem.csr")
    return _rsa

@pytest.fixture
def csr_ecdsa():
    global _ecdsa
    if _ecdsa is None:
        _ecdsa = CSR.load_pem_file("test/resources/ecdsa.pem.csr")
    return _ecdsa

#
# Test getters
#
def test_subject_dn(csr_rsa):
    assert csr_rsa.get_subject_dn() == "CN=user,O=Company"

def test_san(csr_rsa):
    values = csr_rsa.get_san()
    assert ('DNS', 'www.example.com') in values
    assert ('IP', '127.0.0.1') in values
    assert ('URI', 'http://www.example.com') in values
    assert ('RegID', '1.3.6.1.4.1.343') in values
    assert ('Email', 'email@example.com') in values
    assert ('DirName', 'CN=machine,O=Company,DC=LDAP') in values
    assert ('UPN', 'upn@example.com') in values
    assert ('Mailbox', 'smtpUTF8Mailbox@example.com') in values
    assert ('Other', ('1.3.6.1.4.1.311.25.1', '23831111111111fb772f94')) in values

def test_rsa_key_type(csr_rsa):
    assert csr_rsa.get_key_type() == "RSA"

def test_rsa_key_size(csr_rsa):
    assert csr_rsa.get_key_size() == 3072

def test_rsa_key_curve(csr_rsa):
    assert csr_rsa.get_key_curve() == None

def test_ecdsa_key_type(csr_ecdsa):
    assert csr_ecdsa.get_key_type() == "ECDSA"

def test_ecdsa_key_size(csr_ecdsa):
    assert csr_ecdsa.get_key_size() == 256

def test_ecdsa_key_curve(csr_ecdsa):
    assert csr_ecdsa.get_key_curve() == "secp256r1"

#
# Test CSR generation
#
def test_generate_rsa_csr():
    CSR.generate(
        file_csr="test/tmp/rsa.csr", file_key="test/tmp/rsa.key",
        key_type='RSA', key_size=1024,
        CN='test', OU='test', O='test', C='FR',
        DNS=['test.fr', 'test.loc'], RegID=['1.2.3.4'],
        Email=['test@email.com'], IP=["127.0.0.1"]
    )
    csr = CSR.load_pem_file("test/tmp/rsa.csr")
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

def test_generate_ecdsa_csr():
    CSR.generate(
        file_csr="test/tmp/ecdsa.csr", file_key="test/tmp/ecdsa.key",
        key_type='ECDSA', key_curve=ec.BrainpoolP512R1,
        CN='test', OU='test', O='test', C='FR',
        DNS=['test.fr', 'test.loc'], RegID=['1.2.3.4'],
        Email=['test@email.com'], IP=["127.0.0.1"]
    )
    csr = CSR.load_pem_file("test/tmp/ecdsa.csr")
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

def test_generate_rdn_csr():
    names = {
        RDN.CommonName: "RDNs",
        RDN.BusinessCategory: 'BC',
        RDN.DNQualifier: 'DNQ',
        RDN.Generation: 'Gen',
        RDN.GivenName: 'GN',
        RDN.Initials: 'Initials',
    }
    CSR.generate(
        file_csr="test/tmp/rdn.csr", file_key="test/tmp/rdn.key",
        key_type='ECDSA', key_curve=ec.BrainpoolP512R1,
        Names=names,
    )
    csr = CSR.load_pem_file("test/tmp/ecdsa.csr")
    assert isinstance(csr._obj, cryptography.x509.CertificateSigningRequest)

#
# Test persistance
#
def test_save_rsa(csr_rsa):
    csr_rsa.save("test/tmp/rsa.pem.csr", "PEM")
    csr_rsa.save("test/tmp/rsa.der.csr", "DER")

def test_save_ecdsa(csr_ecdsa):
    csr_ecdsa.save("test/tmp/ecdsa.pem.csr", "PEM")
    csr_ecdsa.save("test/tmp/ecdsa.der.csr", "DER")

#
# Test dumpers
#
def test_dump_rsa(csr_rsa):
    print(csr_rsa.dump("DER"))
    print(csr_rsa.dump("BASE64"))
    print(csr_rsa.dump("PEM"))
    print(csr_rsa.dump("TEXT"))

def test_dump_ecdsa(csr_ecdsa):
    print(csr_ecdsa.dump("DER"))
    print(csr_ecdsa.dump("BASE64"))
    print(csr_ecdsa.dump("PEM"))
    print(csr_ecdsa.dump("TEXT"))
