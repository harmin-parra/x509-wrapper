from X509_wrapper import KEY

# RSA
key = KEY.load_public_key_pem_file("files/rsa.pem.pub.key")
key = KEY.load_public_key_der_file("files/rsa.der.pub.key")
b64 = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtdktj74lBI096UamLayC756IXPNkTkgCtG8Vxts7sdFKbWFJxHdfcoMCtEwDQ0Mul7/ENG242srOeOlAlqT9oNAcUIklNi6Sg9JnlFxgsEe/t56sEFM1D44qXciBQybt4jJStU2REnU/LMDuD+aTlxNctDhOKM1Cb3jpblgn0WRqO6vVFcZtZaQFnxRyP+Tdh/7xDmf8+YlP49syp2jF52aEJio5Oks05fSmJyYto7ktJiFxlsH5LUbEIIJjGv8okFa8IpDli1RQWLCIKmpnGHd9MITXK5LWUq0Spl9Gl8gkRtknFsv4OzRt1m5GAHwYuRdD4fnDcy8LyuBxAb2fWSSrzFNUJ9Y+LEjeyDQNKZ/Xx6woOtdZUuLlmRNmuBJGKIsagS9Fs2E+vvitHLe47YR3P3GRntqGf7898Aa0+99l4FRPvltGuahxu6yOMDzJrSpmHh8vXcHBF/vn6ALlh8IrHwKEa8KwVpAmp6zQtLnJqLwZ244LCSY83baWeyuDAgMBAAE="
key = KEY.load_public_key_base64(b64)

print("Key Type:", key.get_type())
print("Key Size:", key.get_size())
print("Key Curve:", key.get_curve())
print("Key Digest:", key.get_digest())

print(key.dump("DER"))
print(key.dump("BASE64"))
print(key.dump("PEM"))


# ECDSA
key = KEY.load_public_key_pem_file("files/ecdsa.pem.pub.key")
key = KEY.load_public_key_der_file("files/ecdsa.der.pub.key")
b64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe4w=="
key = KEY.load_public_key_base64(b64)

print("Key Type:", key.get_type())
print("Key Size:", key.get_size())
print("Key Curve:", key.get_curve())
print("Key Digest:", key.get_digest())

print(key.dump("DER"))
print(key.dump("BASE64"))
print(key.dump("PEM"))
