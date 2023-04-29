# X509 Wrapper

`X509_wraper` is a wrapper for the [pyca/cryptography](https://cryptography.io/en/latest/) package.

It allows to query X509 chryptography object attributes in a fast and easy way.

The attribute values are returned as Python primitive and built-in types (`integer`, `string`, `boolean` and `lists`) instead of being returned as instances of [pyca/cryptography](https://cryptography.io/en/latest/) classes like `cryptography.x509.Name`, `cryptography.x509.GeneralName`, `cryptography.x509.AuthorityKeyIdentifier`, `cryptography.x509.CRLDistributionPoints`, `cryptography.x509.Extension`, etc.

## Supported X509 cryptography objects
- Certificate
- Certificate revocation list (CRL)
- Delta certificate revocationlist (Delta CRL)
- Certificate signing request (CSR)
- RSA / ECDSA public and private keys

## Usage

### X509 Certificate

### Loaders
```python
from X509_wrapper import Certificate

# Loading from PEM format file
cert = Certificate.load_pem_file("file.pem")

# Loading from DER format file
cert = Certificate.load_der_file("file.crt")

# Loading from PEM base64 string
b64 = "MIIFEDCCA3igAwIB............"
cert = Certificate.load_base64(b64)
```

### Getters
```python
print("SubjectDN:", cert.get_subject_dn())
print("IssuerDN:", cert.get_issuer_dn())
print("Serial number (INT format):", cert.get_serial_number("INT"))
print("Serial number (HEX format):", cert.get_serial_number())
print("Authority Key Identifier:", cert.get_aki())
print("Subject Key Identifier:", cert.get_ski())
print("Subject Alternative Name:", cert.get_san_list())
print("Issuer Alternative Name:", cert.get_ian_list())
print("Has Expired:", cert.has_expired())
print("Signature algorithm:", cert.get_signature_algorithm())
print("CRL distribution points", cert.get_crl_dp())
print("Delta CRL distribution points", cert.get_delta_dp())
print("Authority Information Access:", cert.get_authority_info_access())
print("Certificate Policies:", cert.get_policies())

print("Key Type:", cert.get_key_type())
print("Key Size:", cert.get_key_size())
print("Key Curve:", cert.get_key_curve())

```
