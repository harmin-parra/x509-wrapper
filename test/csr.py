from cryptography.hazmat.primitives.asymmetric import ec
from X509_wrapper import CSR

# RSA
csr = CSR.load_der_file("files/rsa.der.csr")
csr = CSR.load_pem_file("files/rsa.pem.csr")
b64 = "MIIEVDCCArwCAQAwIDEQMA4GA1UECgwHQ29tcGFueTEMMAoGA1UEAwwDcnNhMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtdktj74lBI096UamLayC756IXPNkTkgCtG8Vxts7sdFKbWFJxHdfcoMCtEwDQ0Mul7/ENG242srOeOlAlqT9oNAcUIklNi6Sg9JnlFxgsEe/t56sEFM1D44qXciBQybt4jJStU2REnU/LMDuD+aTlxNctDhOKM1Cb3jpblgn0WRqO6vVFcZtZaQFnxRyP+Tdh/7xDmf8+YlP49syp2jF52aEJio5Oks05fSmJyYto7ktJiFxlsH5LUbEIIJjGv8okFa8IpDli1RQWLCIKmpnGHd9MITXK5LWUq0Spl9Gl8gkRtknFsv4OzRt1m5GAHwYuRdD4fnDcy8LyuBxAb2fWSSrzFNUJ9Y+LEjeyDQNKZ/Xx6woOtdZUuLlmRNmuBJGKIsagS9Fs2E+vvitHLe47YR3P3GRntqGf7898Aa0+99l4FRPvltGuahxu6yOMDzJrSpmHh8vXcHBF/vn6ALlh8IrHwKEa8KwVpAmp6zQtLnJqLwZ244LCSY83baWeyuDAgMBAAGgge4wgesGCSqGSIb3DQEJDjGB3TCB2jCB1wYDVR0RBIHPMIHMghVyc2EuZGV2Lm9wZW50cnVzdC5jb22CE3JzYS5kZXYuaWRub21pYy5jb22CCWxvY2FsaG9zdIcEfwAAAYYWaHR0cDovL3d3dy5pZG5vbWljLmNvbYERZW1haWxAaWRub21pYy5jb22gHwYKKwYBBAGCNxQCA6ARDA91cG5AaWRub21pYy5jb22IBysGAQQBglekODA2MRQwEgYKCZImiZPyLGQBGRYETERBUDEQMA4GA1UECgwHQ29tcGFueTEMMAoGA1UEAwwDcnNhMA0GCSqGSIb3DQEBCwUAA4IBgQAesVaJq4HTKyvHxf0J3V0caksDW7irGKg75JfFIrguTQjfklGQK5IJYsTtwSaDZBbQXCgKEfQ4mv8/9lys2Kja1bA4vBI6YdQm1uPGFNA/IAlwx9eeM9wOEPDw0Yfs+dc0//OiSlLTnNxWHgYgVZ5Sm7yyhMIZl0WBaQ5T7zVjQVLYbLhT1fnLQycU0o2pn/rsc+x8d6tOQtCbfz09xKucd+poa/n32/pzfeuiciAevpWrgCY7sjOc3zMgx3ozPVx3xWw8ca6QyuyBMrA867SHdm0P9ID0LpC7w+P+pIY1PV1eu6aMqsLH6A1duTlXiXKZSP6UVgeQ7WiquE+Lkf2LMk6QGbuRGlVHo+fIdgn+3SHwmUMIfsMyuO/D7NMeP3KRDkk6yN6cArCdhcJkBfJtQ51a3OzUt3w8/QejxWSNDjbcMDSLdsk5+/9vOEn7S8ksSfvuZgH/qHnitvIOgTv3aBBqPHFMfEc3Qfy0OzFSpXtIsaM37wqsiU67XSBN6e4="
csr = CSR.load_base64(b64)

print(csr.get_subject_dn())
print(csr.get_san_list())
print(csr.get_signature_algorithm())

print(csr.get_key_type())
print(csr.get_key_size())

print(csr.dump("DER"))
print(csr.dump("PEM"))
print(csr.dump("BASE64"))

# ECDSA
csr = CSR.load_pem_file("files/ecdsa.pem.csr")
csr = CSR.load_der_file("files/ecdsa.der.csr")
b64 = "MIHdMIGEAgEAMCIxEDAOBgNVBAoMB0NvbXBhbnkxDjAMBgNVBAMMBWVjZHNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe46AAMAoGCCqGSM49BAMCA0gAMEUCIFp1yT6cTFPfF4bjWonGbuqnKpzqztSzh5eHX2+DRAeEAiEAyzCL4G1Uxlxdo/o3PTYUBCyPUQFCUAe22H1AB/ta1Qg="
csr = CSR.load_base64(b64)

print(csr.get_subject_dn())
print(csr.get_san_list())
print(csr.get_signature_algorithm())

print(csr.get_key_type())
print(csr.get_key_size())
print(csr.get_key_curve())

print(csr.dump("DER"))
print(csr.dump("PEM"))
print(csr.dump("BASE64"))

# Constructor
CSR.generate(file_csr="tmp/rsa.csr", file_key="tmp/rsa.key", \
                     key_type='RSA', key_size=1024, \
                     CN='test', OU='test', O='test', C='FR',\
                     DNS=['test.fr', 'test.loc'], RegID=['1.2.3.4'], \
                     Email=['test@email.com'], IP=["127.0.0.1"])

CSR.generate(file_csr="tmp/ecdsa.csr", file_key="tmp/ecdsa.key", \
                     key_type='ECDSA', key_curve=ec.BrainpoolP512R1, \
                     CN='test', OU='test', O='test', C='FR',\
                     DNS=['test.fr', 'test.loc'], RegID=['1.2.3.4'], \
                     Email=['test@email.com'], IP=["127.0.0.1"])
