from wrapper.x509 import KEY
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
import os
import pytest


#
# Test loaders
#
def test_load_rsa_der_file():
    key = KEY.load_private_key_der_file(f"test{os.sep}resources{os.sep}rsa.der.priv.key")
    assert isinstance(key._obj, RSAPrivateKey)

def test_load_rsa_pem_file():
    key = KEY.load_private_key_pem_file(f"test{os.sep}resources{os.sep}rsa.pem.priv.key")
    assert isinstance(key._obj, RSAPrivateKey)

def test_load_rsa_base64_string():
    b64 = "MIIG4wIBAAKCAYEAtdktj74lBI096UamLayC756IXPNkTkgCtG8Vxts7sdFKbWFJxHdfcoMCtEwDQ0Mul7/ENG242srOeOlAlqT9oNAcUIklNi6Sg9JnlFxgsEe/t56sEFM1D44qXciBQybt4jJStU2REnU/LMDuD+aTlxNctDhOKM1Cb3jpblgn0WRqO6vVFcZtZaQFnxRyP+Tdh/7xDmf8+YlP49syp2jF52aEJio5Oks05fSmJyYto7ktJiFxlsH5LUbEIIJjGv8okFa8IpDli1RQWLCIKmpnGHd9MITXK5LWUq0Spl9Gl8gkRtknFsv4OzRt1m5GAHwYuRdD4fnDcy8LyuBxAb2fWSSrzFNUJ9Y+LEjeyDQNKZ/Xx6woOtdZUuLlmRNmuBJGKIsagS9Fs2E+vvitHLe47YR3P3GRntqGf7898Aa0+99l4FRPvltGuahxu6yOMDzJrSpmHh8vXcHBF/vn6ALlh8IrHwKEa8KwVpAmp6zQtLnJqLwZ244LCSY83baWeyuDAgMBAAECggGAAcdTA8HnWMkM3vg67d1vFmrliIs04vMfW6Zufxhr2Axk/vbhotNMErGnWB4aNhE1JnTQtXaRRUqQhGw7nn2UoXsHm94LiCEie7mWG8RfibnZ7TDXG/3EWheY4Hvyj7aUww6c8nsEvTp6WLS2X19w+BxPXs/iK9H+IVr8ZYDlOs4Rn+3JUsIzFbhp+alYiLlzVT4wG2T2+3XVWzQspaiHrwC4sCrfjmtn5AvliCJ+dch84Y+YLdJN3px/lJXR5FS0i58Hy+r4aqyGAcEYyZiJPtlXWSyHB9IV5A61FOLW7wYWOZM81gtcrisHRCjWDuB2BHRZC0jj5KE2fV/tMNRjTCQcTk7qedbNk6r0hUes8B8Xfy3hDFYCknZjocBxs1sgn4ittxZ+Y0kuezjSL0P3HE1N+cUzlCW1SsBLPV9q4IsQ6yVEPvQ2QQ5jtjFQJgirGU4EVPcaE95MNzvfABj2OF4NlhSMc1I/ynL8/wv7lcrr3+f3ydoFkUGAJR2ORNOhAoHBAO5OUOPm1SQXaMD3LjwxfexLbFgligwiQ5qm+FpaROdBr1KSmAGN8Fw6g9h4HBtefwYB87T4uB74o/+iItYMYYz04P/RLcUgLTAY1iErvasajPrnGwEQzUBmmIn/SQfdPVQYWqgh01iTp9DTOIHQrnBOJbkl+ll/TYHJmZCpmIccbjLnPiE/BZY/3Udiou7zeMEH3+MdedZ1eGM176A5kw18YHYyRt9+V0F/ebfnjm9oI3UKH6I4oWEIjAAs/viUkwKBwQDDWbmLCcfb4Sz5IV8+xFs9gqbOCcDNhXS1Y4BM2Yvtnx5ss9LdQCM3Wsn3h9lV7oQqwAwHfS3d9HXv0dlAOpNzwvvBPL6lS6qOi9ClW0suojMg41A8JgjjX+hcILcg5l2iAaBj87JXx7Egvw2IEmw6v/4GbJmHI4ivDGj/pn8eHqO5VVlpzrFBgQjW7LpkgSz9QwTW/UyBKE58Bvl9t59s++zz153Zd2xfb/LQOmxLgbUMOEor1KVzxUTJsC2F01ECgcBNuU9atYvo5JWu8i+rRD0c15CzwzKeOIKyKykvVufIQT0sglF/mEq/2fnsnWgVaSGm1PYmnUR4HYJnuvr/szQR5ECKTzBNbewvFrqoQPrwlo1KvBurok4/Zfb0c0XfgcIh7nuLANVMu4PtcSap+GUcjfBxzbg0fnfKD/W9IAN2dchfY9p4v3RUB+plAP/BTbmhw667BX8ael/Ug9/u8zhKGrnfcxB4jl1pKGmLmMN1BJMj9jRRFYVU/5Oh7wsOCm8CgcEAotedorhxgOpRGg/mnKUERd8ue1yH+wq/wiECp41FZryYmRbBtSus74zgBVaaJlbgl95laKzB2l7ZHSP6DN+HYR1tzaR8a8AKmi8Uq3LR1jrhkg3LKYivKhMd2AZxgZxm+xCOCiPwS9or3ldEyWRKEiNPdz16Mbu+SeV3dXzuREZYRrtOALSK8EbG/ppxuiwwO6JtW2XlK1lVK3CI83JpFGlhGddoPwqdLWVdrJS3B65FJL2bnrPxg/Myp0oUeJUxAoHAKhlGkCGgEZHZFaV1w+xfC4hCyIhZUyz8Wfe0EhMh7j8rHYu3sbyY7/swmhGbgyg8G23twnZ4D52f7pTu+URaL6iFK8/ssP6sKi/jqa8x858N35Tn+wSU2HolGO2TI99CnPOuN3/HmLjSM+tZrvwgLRdnykSte+n8YQ4cAfysbq5lhy4PbWFIq2BH8wzuJOnhp4i7n6Qyi+7uLVY/1CyhMfEz3qqfFNuSzwiahvaF+Xwgc5m8y9q89FOBs+GzjBSn"
    key = KEY.load_private_key_base64(b64)
    assert isinstance(key._obj, RSAPrivateKey)

def test_load_ecdsa_der_file():
    key = KEY.load_private_key_der_file(f"test{os.sep}resources{os.sep}ecdsa.der.priv.key")
    assert isinstance(key._obj, EllipticCurvePrivateKey)

def test_load_ecdsa_pem_file():
    key = KEY.load_private_key_pem_file(f"test{os.sep}resources{os.sep}ecdsa.pem.priv.key")
    assert isinstance(key._obj, EllipticCurvePrivateKey)

"""
def test_load_ecdsa_base64_string():
    b64 = "MHcCAQEEIOny4+FGFw7nQHesdJvzNA8x82DKACsxSyqZnmZvvy7GoAoGCCqGSM49AwEHoUQDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe4w=="
    key = KEY.load_private_key_base64(b64)
    assert isinstance(key._obj, EllipticCurvePrivateKey)
"""

#
# Fixtures for getter tests
#
_rsa = None
_ecdsa = None

@pytest.fixture
def key_rsa():
    global _rsa
    if _rsa is None:
        _rsa = KEY.load_private_key_pem_file(f"test{os.sep}resources{os.sep}rsa.pem.priv.key")
    return _rsa

@pytest.fixture
def key_ecdsa():
    global _ecdsa
    if _ecdsa is None:
        _ecdsa = KEY.load_private_key_pem_file(f"test{os.sep}resources{os.sep}ecdsa.pem.priv.key")
    return _ecdsa

#
# Test getters
#
def test_rsa_key_type(key_rsa):
    assert key_rsa.get_type() == "RSA"

def test_rsa_key_size(key_rsa):
    assert key_rsa.get_size() == 3072

def test_rsa_key_curve(key_rsa):
    assert key_rsa.get_curve() is None

def test_ecdsa_key_type(key_ecdsa):
    assert key_ecdsa.get_type() == "ECDSA"

def test_ecdsa_key_size(key_ecdsa):
    assert key_ecdsa.get_size() == 256

def test_ecdsa_key_curve(key_ecdsa):
    assert key_ecdsa.get_curve() == "secp256r1"

#
# Test persistance
#
def test_save_rsa(key_rsa):
    key_rsa.save(f"test{os.sep}tmp{os.sep}rsa.pem.priv.key", "PEM")
    key_rsa.save(f"test{os.sep}tmp{os.sep}rsa.der.priv.key", "DER")
    
def test_save_ecdsa(key_ecdsa):
    key_ecdsa.save(f"test{os.sep}tmp{os.sep}ecdsa.pem.priv.key", "PEM")
    key_ecdsa.save(f"test{os.sep}tmp{os.sep}ecdsa.der.priv.key", "DER")

#
# Test dumpers
#
def test_dump_rsa(key_rsa):
    print(key_rsa.dump("DER"), '\n')
    print(key_rsa.dump("BASE64"), '\n')
    print(key_rsa.dump("PEM"), '\n')
    print(key_rsa.dump("TEXT"), '\n')

def test_dump_ecdsa(key_ecdsa):
    print(key_ecdsa.dump("DER"), '\n')
    print(key_ecdsa.dump("BASE64"), '\n')
    print(key_ecdsa.dump("PEM"), '\n')
    print(key_ecdsa.dump("TEXT"), '\n')
