from wrapper.x509 import KEY
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
import pytest


#
# Test loaders
#
def test_load_rsa_der_file():
    key = KEY.load_public_key_der_file("test/resources/rsa.der.pub.key")
    assert isinstance(key._obj, RSAPublicKey)

def test_load_rsa_pem_file():
    key = KEY.load_public_key_pem_file("test/resources/rsa.pem.pub.key")
    assert isinstance(key._obj, RSAPublicKey)

def test_load_rsa_base64_string():
    b64 = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtdktj74lBI096UamLayC756IXPNkTkgCtG8Vxts7sdFKbWFJxHdfcoMCtEwDQ0Mul7/ENG242srOeOlAlqT9oNAcUIklNi6Sg9JnlFxgsEe/t56sEFM1D44qXciBQybt4jJStU2REnU/LMDuD+aTlxNctDhOKM1Cb3jpblgn0WRqO6vVFcZtZaQFnxRyP+Tdh/7xDmf8+YlP49syp2jF52aEJio5Oks05fSmJyYto7ktJiFxlsH5LUbEIIJjGv8okFa8IpDli1RQWLCIKmpnGHd9MITXK5LWUq0Spl9Gl8gkRtknFsv4OzRt1m5GAHwYuRdD4fnDcy8LyuBxAb2fWSSrzFNUJ9Y+LEjeyDQNKZ/Xx6woOtdZUuLlmRNmuBJGKIsagS9Fs2E+vvitHLe47YR3P3GRntqGf7898Aa0+99l4FRPvltGuahxu6yOMDzJrSpmHh8vXcHBF/vn6ALlh8IrHwKEa8KwVpAmp6zQtLnJqLwZ244LCSY83baWeyuDAgMBAAE="
    key = KEY.load_public_key_base64(b64)
    assert isinstance(key._obj, RSAPublicKey)

def test_load_ecdsa_der_file():
    key = KEY.load_public_key_der_file("test/resources/ecdsa.der.pub.key")
    assert isinstance(key._obj, EllipticCurvePublicKey)

def test_load_ecdsa_pem_file():
    key = KEY.load_public_key_pem_file("test/resources/ecdsa.pem.pub.key")
    assert isinstance(key._obj, EllipticCurvePublicKey)

def test_load_ecdsa_base64_string():
    b64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe4w=="
    key = KEY.load_public_key_base64(b64)
    assert isinstance(key._obj, EllipticCurvePublicKey)

#
# Fixtures for getter tests
#
_rsa = None
_ecdsa = None

@pytest.fixture
def key_rsa():
    global _rsa
    if _rsa is None:
        _rsa = KEY.load_public_key_pem_file("test/resources/rsa.pem.pub.key")
    return _rsa

@pytest.fixture
def key_ecdsa():
    global _ecdsa
    if _ecdsa is None:
        _ecdsa = KEY.load_public_key_pem_file("test/resources/ecdsa.pem.pub.key")
    return _ecdsa

#
# Test getters
#
def test_rsa_key_type(key_rsa):
    assert key_rsa.get_type() == "RSA"

def test_rsa_key_size(key_rsa):
    assert key_rsa.get_size() == 3072

def test_rsa_key_curve(key_rsa):
    assert key_rsa.get_curve() == None

def test_ecdsa_key_type(key_ecdsa):
    assert key_ecdsa.get_type() == "ECDSA"

def test_ecdsa_key_size(key_ecdsa):
    assert key_ecdsa.get_size() == 256

def test_ecdsa_key_curve(key_ecdsa):
    assert key_ecdsa.get_curve() == "secp256r1"

#
# Test dumpers
#
def test_dump_rsa(key_rsa):
    print(key_rsa.dump("DER"))
    print(key_rsa.dump("BASE64"))
    print(key_rsa.dump("PEM"))
    print(key_rsa.dump("TEXT"))

def test_dump_ecdsa(key_ecdsa):
    print(key_ecdsa.dump("DER"))
    print(key_ecdsa.dump("BASE64"))
    print(key_ecdsa.dump("PEM"))
    print(key_ecdsa.dump("TEXT"))
