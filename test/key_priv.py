from X509_wrapper import KEY

# RSA
key = KEY.load_private_key_pem_file("resources/rsa.pem.priv.key")
key = KEY.load_private_key_der_file("resources/rsa.der.priv.key")
b64 = "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"
key = KEY.load_private_key_base64(b64)

print(key.get_type())
print(key.get_size())
print(key.get_curve())
print(key.get_digest())

print(key.dump("DER"))
print(key.dump("BASE64"))
print(key.dump("PEM"))

# ECDSA
key = KEY.load_private_key_pem_file("resources/ecdsa.pem.priv.key")
key = KEY.load_private_key_der_file("resources/ecdsa.der.priv.key")
b64 = "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"
#key = KEY.load_private_key_base64(b64)

print(key.get_type())
print(key.get_size())
print(key.get_curve())
print(key.get_digest())

print(key.dump("DER"))
print(key.dump("BASE64"))
print(key.dump("PEM"))
