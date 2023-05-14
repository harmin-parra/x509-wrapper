from wrapper.x509 import Certificate
import cryptography.x509
import pytest

#
# Test loaders
#
def test_load_rsa_der_file():
    cert = Certificate.load_der_file("test/resources/rsa.crt")
    assert isinstance(cert._obj, cryptography.x509.Certificate)

def test_load_rsa_pem_file():
    cert = Certificate.load_pem_file("test/resources/rsa.pem")
    assert isinstance(cert._obj, cryptography.x509.Certificate)

def test_load_rsa_base64_string():
    b64 = "MIIHFzCCBX+gAwIBAgIUEXUPiXw/VfU2dnAjrQWG5ASiuHgwDQYJKoZIhvcNAQELBQAwJzEQMA4GA1UECgwHQ29tcGFueTETMBEGA1UEAwwKRXhhbXBsZSBDQTAeFw0yMzA0MzAxMDI5NThaFw0zMzA0MjgxNDIwMzlaMD0xCzAJBgNVBAYTAkZSMRAwDgYDVQQKDAdDb21wYW55MQ0wCwYDVQQLDARVbml0MQ0wCwYDVQQDDAR1c2VyMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtdktj74lBI096UamLayC756IXPNkTkgCtG8Vxts7sdFKbWFJxHdfcoMCtEwDQ0Mul7/ENG242srOeOlAlqT9oNAcUIklNi6Sg9JnlFxgsEe/t56sEFM1D44qXciBQybt4jJStU2REnU/LMDuD+aTlxNctDhOKM1Cb3jpblgn0WRqO6vVFcZtZaQFnxRyP+Tdh/7xDmf8+YlP49syp2jF52aEJio5Oks05fSmJyYto7ktJiFxlsH5LUbEIIJjGv8okFa8IpDli1RQWLCIKmpnGHd9MITXK5LWUq0Spl9Gl8gkRtknFsv4OzRt1m5GAHwYuRdD4fnDcy8LyuBxAb2fWSSrzFNUJ9Y+LEjeyDQNKZ/Xx6woOtdZUuLlmRNmuBJGKIsagS9Fs2E+vvitHLe47YR3P3GRntqGf7898Aa0+99l4FRPvltGuahxu6yOMDzJrSpmHh8vXcHBF/vn6ALlh8IrHwKEa8KwVpAmp6zQtLnJqLwZ244LCSY83baWeyuDAgMBAAGjggMjMIIDHzAdBgNVHQ4EFgQUE5yuECfctcpFfIFVi0aKjmm3xDEwHwYDVR0jBBgwFoAUxv34wwz3JCJMZ/VEnztZmjdT71YwCwYDVR0PBAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMEEGA1UdHwQ6MDgwGqAYoBaGFGh0dHA6Ly9sb2NhbGhvc3QvY3JsMBqgGKAWhhRsZGFwOi8vbG9jYWxob3N0L2NybDBFBgNVHS4EPjA8MBygGqAYhhZodHRwOi8vbG9jYWxob3N0L2RlbHRhMBygGqAYhhZsZGFwOi8vbG9jYWxob3N0L2RlbHRhMIHlBgNVHREEgd0wgdqCD3d3dy5leGFtcGxlLmNvbYcEfwAAAYgDKgMEgRFlbWFpbEBleGFtcGxlLmNvbaAfBgorBgEEAYI3FAIDoBEMD3VwbkBleGFtcGxlLmNvbaQ8MDoxFDASBgoJkiaJk/IsZAEZFgRMREFQMRAwDgYDVQQKDAdFeGFtcGxlMRAwDgYDVQQDDAdtYWNoaW5loB8GCSsGAQQBgjcZAaASBBCsSykGqtZdT6mcTLywamXZoCkGCCsGAQUFBwgJoB0MG3NtdHBVVEY4TWFpbGJveEBleGFtcGxlLmNvbTAcBgNVHRIEFTATgRFhZG1pbkBleGFtcGxlLmNvbTCBlAYDVR0gBIGMMIGJMFIGDCsGAQQBsC0FAQEBATBCMCEGCCsGAQUFBwIBFhVodHRwOi8vbG9jYWxob3N0L2NzcDEwHQYIKwYBBQUHAgIwETAKDANvcmcwAwIBAQwDdHh0MDMGDCsGAQQBsC0FAQEBAjAjMCEGCCsGAQUFBwIBFhVodHRwOi8vbG9jYWxob3N0L2NwczIwEgYJKwYBBQUHMAEFAQH/BAIFADApBgkrBgEEAYI3GQIEHDAaoBgGCisGAQQBgjcZAgGgCgQIUy0xLTUtNDcwUgYIKwYBBQUHAQEERjBEMCEGCCsGAQUFBzABhhVodHRwOi8vbG9jYWxob3N0L29jc3AwHwYIKwYBBQUHMAKGE2h0dHA6Ly9sb2NhbGhvc3QvY2EwDQYJKoZIhvcNAQELBQADggGBADn1m3qO/pHdt2a4ompS5h87/lPLaFFZzceNzyuiOjVU1PVCJXw64Pk5qK15FN22AGyG1w4DA5On7dppcRW6+qIzWyqUX9EQMkDAjNTm2sJ3yOU9pK7LH5MR/cOEFCdV8Y3TWl90zQszjzLMJkHPIOSpxULaz2LxZXmXZqfnCi0W8Dx0OSsLK+DbbuvQyI2ZuJky4+Saqsdg43cw6tkvuANrkrXgy4/ANheXY3Wj1+Pv2ZSuXrUfT66FLfk1WWQN64aGjuA5Ckzjju8Mo3jtX1Lhb/kHL+h4Jz+nX54yVlDRWXUW3/Z2DPJX7ueuaDTvinZs94WlJb+sqlDiYQfYkG48V+/nfSmTfji+JZZNPJ0YvwXXn7ld90TLag+Djv3CWFnydKWxBIq6ou2FFVxKBwwNT1iL6cLNH88u16d7UUl5lAO0Bp0GcCOVnaqOPlwQ2Rls4FZRpEFVCGGOTyj85fp7NVrX7MRFBnf9Glc9HdjlRVYU+kNeKes9vEh8tWRGYA=="
    cert = Certificate.load_base64(b64)
    assert isinstance(cert._obj, cryptography.x509.Certificate)

def test_load_ecdsa_der_file():
    cert = Certificate.load_der_file("test/resources/ecdsa.crt")
    assert isinstance(cert._obj, cryptography.x509.Certificate)

def test_load_ecdsa_pem_file():
    cert = Certificate.load_pem_file("test/resources/ecdsa.pem")
    assert isinstance(cert._obj, cryptography.x509.Certificate)

def test_load_ecdsa_base64_string():
    b64 = "MIIFzDCCBDSgAwIBAgIUFkdtoV63MX/ASregpa7Zy5LbZtYwDQYJKoZIhvcNAQELBQAwJzEQMA4GA1UECgwHQ29tcGFueTETMBEGA1UEAwwKRXhhbXBsZSBDQTAeFw0yMzA0MzAxMDMwNTFaFw0zMzA0MjgxNDIwMzlaMD0xCzAJBgNVBAYTAkZSMRAwDgYDVQQKDAdDb21wYW55MQ0wCwYDVQQLDARVbml0MQ0wCwYDVQQDDAR1c2VyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe46OCAyMwggMfMB0GA1UdDgQWBBTdc0FYJUsricMg3iWZF47m/miucDAfBgNVHSMEGDAWgBTG/fjDDPckIkxn9USfO1maN1PvVjALBgNVHQ8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwQQYDVR0fBDowODAaoBigFoYUaHR0cDovL2xvY2FsaG9zdC9jcmwwGqAYoBaGFGxkYXA6Ly9sb2NhbGhvc3QvY3JsMEUGA1UdLgQ+MDwwHKAaoBiGFmh0dHA6Ly9sb2NhbGhvc3QvZGVsdGEwHKAaoBiGFmxkYXA6Ly9sb2NhbGhvc3QvZGVsdGEwgeUGA1UdEQSB3TCB2oIPd3d3LmV4YW1wbGUuY29thwR/AAABiAMqAwSBEWVtYWlsQGV4YW1wbGUuY29toB8GCisGAQQBgjcUAgOgEQwPdXBuQGV4YW1wbGUuY29tpDwwOjEUMBIGCgmSJomT8ixkARkWBExEQVAxEDAOBgNVBAoMB0V4YW1wbGUxEDAOBgNVBAMMB21hY2hpbmWgHwYJKwYBBAGCNxkBoBIEEKxLKQaq1l1PqZxMvLBqZdmgKQYIKwYBBQUHCAmgHQwbc210cFVURjhNYWlsYm94QGV4YW1wbGUuY29tMBwGA1UdEgQVMBOBEWFkbWluQGV4YW1wbGUuY29tMIGUBgNVHSAEgYwwgYkwUgYMKwYBBAGwLQUBAQEBMEIwIQYIKwYBBQUHAgEWFWh0dHA6Ly9sb2NhbGhvc3QvY3NwMTAdBggrBgEFBQcCAjARMAoMA29yZzADAgEBDAN0eHQwMwYMKwYBBAGwLQUBAQECMCMwIQYIKwYBBQUHAgEWFWh0dHA6Ly9sb2NhbGhvc3QvY3BzMjASBgkrBgEFBQcwAQUBAf8EAgUAMCkGCSsGAQQBgjcZAgQcMBqgGAYKKwYBBAGCNxkCAaAKBAhTLTEtNS00NzBSBggrBgEFBQcBAQRGMEQwIQYIKwYBBQUHMAGGFWh0dHA6Ly9sb2NhbGhvc3Qvb2NzcDAfBggrBgEFBQcwAoYTaHR0cDovL2xvY2FsaG9zdC9jYTANBgkqhkiG9w0BAQsFAAOCAYEAdR3qc+Iq2/cv/hFw2hNG7jN3vw+B38IiSalI0rvYpWJmVne8JR9g7HSD00drU2cTPG0iWNU+GrNND+WW70yhmPNCFIj3KD3SmB9Qks3PwkRaMg/ZqIZkCNNVU9/DolORcVQmig7gFlnzAdybElsbD27NNFonxbGwnbs7SurwLYjLawG/NpvGZGb8HQk9drsl5XzDV1V7bto0ODgnvY/ixvymaHWa4+Ysm6EzImxFbFuDCO2TKmBuP1zuK9QXuo2VbxYRC9yYTMK+YmYR78YQqvozcKHYtvjwjGF4og5lEePbdrj19KZ8CBe8aJyRPz1jxoJ5HnffeMde73AUjjmyarWNn5AMl87Q8vgJR8yZfagHFAdMzUrxUoIXG3p8jUBp9mW59eowT5172016esofi/Jbj1y3tIu7VgD8C1apvVcm9fK/nkdxnT0DIu2OciXxPFaZQZc12o+uIo1R9JGaIPY58cSz9MgND1XVawpL01TDM7gCD1wcM1Eyq/QYB8mw"
    cert = Certificate.load_base64(b64)
    assert isinstance(cert._obj, cryptography.x509.Certificate)

#
# Fixtures for getter tests
#
_rsa = None
_ecdsa = None

@pytest.fixture
def cert_rsa():
    global _rsa
    if _rsa is None:
        _rsa = Certificate.load_pem_file("test/resources/rsa.pem")
    return _rsa

@pytest.fixture
def cert_ecdsa():
    global _ecdsa
    if _ecdsa is None:
        _ecdsa = Certificate.load_pem_file("test/resources/ecdsa.pem")
    return _ecdsa

#
# Test getters
#
def test_subject_dn(cert_rsa):
    assert cert_rsa.get_subject_dn() == "CN=user,OU=Unit,O=Company,C=FR"

def test_issuer_dn(cert_rsa):
    assert cert_rsa.get_issuer_dn() == "CN=Example CA,O=Company"

def test_serial_number(cert_rsa):
    assert cert_rsa.get_serial_number('HEX') == "2A79A6418BE1AC366DE659ADA524BDEB6CFB852B"
    assert cert_rsa.get_serial_number('INT') == 242490485487376438573919918375649752458632856875
    assert cert_rsa.get_serial_number() == cert_rsa.get_serial_number('HEX')

def test_aki(cert_rsa):
    assert cert_rsa.get_aki() == "c6fdf8c30cf724224c67f5449f3b599a3753ef56"

def test_ski(cert_rsa):
    assert cert_rsa.get_ski() == "a435986d745138575a7e4d50de8f4c24edaaa8e6"

def test_san(cert_rsa):
    values = cert_rsa.get_san()
    assert ('DNS', 'www.example.com') in values
    assert ('IP','127.0.0.1') in values
    assert ('URI','http://www.example.com') in values
    assert ('RegID','1.2.3.4') in values
    assert ('Email','email@example.com') in values
    assert ('DirName','CN=machine,O=Example,DC=LDAP') in values
    assert ('UPN','upn@example.com') in values
    assert ('Mailbox','smtpUTF8Mailbox@example.com') in values
    assert ('Other', ('1.3.6.1.4.1.311.25.1', 'ac4b2906aad65d4fa99c4cbcb06a65d9')) in values

def test_san_empty(cert_ecdsa):
    assert cert_ecdsa.get_san() is None

def test_ian(cert_rsa):
    values = cert_rsa.get_ian()
    assert ('Email', 'admin@example.com') in values

def test_ian_empty(cert_ecdsa):
    assert cert_ecdsa.get_ian() is None

def test_rsa_key_type(cert_rsa):
    assert cert_rsa.get_key_type() == "RSA"

def test_rsa_key_size(cert_rsa):
    assert cert_rsa.get_key_size() == 3072

def test_rsa_key_curve(cert_rsa):
    assert cert_rsa.get_key_curve() == None

def test_ecdsa_key_type(cert_ecdsa):
    assert cert_ecdsa.get_key_type() == "ECDSA"

def test_ecdsa_key_size(cert_ecdsa):
    assert cert_ecdsa.get_key_size() == 256

def test_ecdsa_key_curve(cert_ecdsa):
    assert cert_ecdsa.get_key_curve() == "secp256r1"

def test_CRL_dp(cert_rsa):
    values = cert_rsa.get_crl_dp()
    assert 'http://localhost/crl' in values
    assert 'ldap://localhost/crl' in values

def test_CRL_dp_empty(cert_ecdsa):
    assert cert_ecdsa.get_crl_dp() is None

def test_delta_dp(cert_rsa):
    values = cert_rsa.get_delta_dp()
    assert 'http://localhost/delta' in values
    assert 'ldap://localhost/delta' in values

def test_delta_dp_empty(cert_ecdsa):
    assert cert_ecdsa.get_delta_dp() is None

def test_authority_info_access(cert_rsa):
    values = cert_rsa.get_authority_info_access()
    assert ('OCSP', 'http://localhost/ocsp') in values
    assert ('caIssuers', 'http://localhost/ca') in values

def test_authority_info_access_empty(cert_ecdsa):
    assert cert_ecdsa.get_authority_info_access() is None

def test_sid(cert_rsa):
    assert cert_rsa.get_sid() == 'S-1-5-47'

def test_sid_empty(cert_ecdsa):
    assert cert_ecdsa.get_sid() is None

def test_key_usage(cert_rsa):
    values = cert_rsa.get_key_usage()
    assert values['critical'] == False
    assert values['digital_signature'] == True
    assert values['content_commitment'] == False
    assert values['key_encipherment'] == False
    assert values['data_encipherment'] == False
    assert values['key_agreement'] == False
    assert values['certificate_sign'] == False
    assert values['crl_sign'] == False
    assert values['encipher_only'] == False
    assert values['decipher_only'] == False

def test_extended_key_usage(cert_rsa):
    values = cert_rsa.get_ext_key_usage()
    assert values['critical'] == True
    assert '1.3.6.1.5.5.7.3.3' in values['value']

def test_has_expired_true(cert_ecdsa):
    assert cert_ecdsa.has_expired() == True
    pass
                     
def test_OCSP_nocheck_true(cert_rsa):
    assert cert_rsa.get_ocsp_nocheck() == True

def test_OCSP_nocheck_false(cert_ecdsa):
    assert cert_ecdsa.get_ocsp_nocheck() == None

def test_policies(cert_rsa):
    assert ('1.3.6.1.4.1.6189.5.1.1.1.1', ('csp', 'http://localhost/csp'), ('notice', ('txt1', 'org1', [1]))) in cert_rsa.get_policies()
    assert ('1.3.6.1.4.1.6189.5.1.1.1.2', ('notice', ('txt2', 'org2', []))) in cert_rsa.get_policies()
    assert ('1.3.6.1.4.1.6189.5.1.1.1.3', ('notice', ('txt3', None, None))) in cert_rsa.get_policies()
#
# Test unicode strings
#
def test_subjectDn_unicode():
    cert = Certificate.load_pem_file("test/resources/int1.pem")
    assert cert.get_subject_dn() == "CN=नाम,OU=इकाई,O=संगठन,C=IN"

def test_san_email_unicode1():
    cert = Certificate.load_pem_file("test/resources/int2.pem")
    assert ('Mailbox', '姓名@例子.cn') in cert.get_san()

def test_san_email_unicode2():
    cert = Certificate.load_pem_file("test/resources/int3.pem")
    assert ('Mailbox', 'տիրույթ@example.am') in cert.get_san()

def test_san_upn_unicode():
    cert = Certificate.load_pem_file("test/resources/upn.pem")
    assert ('UPN', '이메일@도메인.kr') in cert.get_san()

#
# Test persistance
#
def test_save_rsa(cert_rsa):
    cert_rsa.save("test/tmp/rsa.pem", "PEM")
    cert_rsa.save("test/tmp/rsa.crt", "DER")
    
def test_save_ecdsa(cert_ecdsa):
    cert_ecdsa.save("test/tmp/ecdsa.pem", "PEM")
    cert_ecdsa.save("test/tmp/ecdsa.crt", "DER")

#
# Test dumpers
#
def test_dump_rsa(cert_rsa):
    print(cert_rsa.dump("DER"))
    print(cert_rsa.dump("BASE64"))
    print(cert_rsa.dump("PEM"))
    print(cert_rsa.dump("TEXT"))

def test_dump_ecdsa(cert_ecdsa):
    print(cert_ecdsa.dump("DER"))
    print(cert_ecdsa.dump("BASE64"))
    print(cert_ecdsa.dump("PEM"))
    print(cert_ecdsa.dump("TEXT"))
