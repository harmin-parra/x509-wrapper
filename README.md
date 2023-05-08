# X.509 Wrapper

`x509-wrapper` is a wrapper for the [pyca/cryptography](https://cryptography.io/en/latest/) package.

It allows to query X.509 cryptography object attributes in a fast and easy way.

The attribute values are returned as Python primitive and built-in types (`integer`, `string`, `boolean` and `list`) instead of being returned as  instances of `pyca/cryptography` classes like `cryptography.x509.Name`, `cryptography.x509.GeneralName`, `cryptography.x509.AuthorityKeyIdentifier`, `cryptography.x509.CRLDistributionPoints`, `cryptography.x509.Extension`, etc.

## Supported X.509 cryptography objects
- Certificate
- Certificate revocation list (CRL)
- Delta certificate revocation list (Delta CRL)
- Certificate signing request (CSR)
- RSA / ECDSA public and private key

## Limitations
### CSR generation with multi-valued RDNs*

No support for CSR generation with multi-valued RDNs
(Example: `CN=user, OU=unit1, OU=unit2, OU=unit3, C=Company`)

*This limitation doesn't apply to CSR loaders.

### CSR generation with SAN*

No support for CSR generation with the following Subject Alternative Name (SAN) types:
  + Directory Name
  + Other Name

*This limitation doesn't apply to CSR loaders.

### Certificate Policies extension

The extraction of Certificate Policies extension needs improvement.

### Loading of ECDSA private and public keys

`pyca/cryptography` doesn't support ECDSA keys with explicit parameters ([#7339](https://github.com/pyca/cryptography/issues/7339), [#5659](https://github.com/pyca/cryptography/issues/5659)).
Therefore, loading ECDSA keys from base64 strings is not supported.

### Parsing public key of ECDSA x509 certificates*
Again, due to issues [#7339](https://github.com/pyca/cryptography/issues/7339) and [#5659](https://github.com/pyca/cryptography/issues/5659), it is not always possible to query the public key size and curve of ECDSA X.509 certificates. 

*This issue doesn't affect the parsing of the ECDSA X.509 certificate itself.

## Prerequisites

Install [pyca/cryptography](https://cryptography.io/en/latest/) package version 35.0.0 or later :

`pip install cryptography>=35.0.0`

## Usage

### X.509 Certificate

### Loaders
```python
from wrapper.x509 import Certificate

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
print("Subject Alternative Name:", cert.get_san())
print("Issuer Alternative Name:", cert.get_ian())
print("Has Expired:", cert.has_expired())
print("Signature algorithm:", cert.get_signature_algorithm())
print("CRL distribution points", cert.get_crl_dp())
print("Delta CRL distribution points", cert.get_delta_dp())
print("Authority Information Access:", cert.get_authority_info_access())
print("Certificate Policies:", cert.get_policies())
print("Microsoft SID:", cert.get_sid())
print("Key usage:", cert.get_key_usage())
print("Extended key usage:", cert.get_ext_key_usage())

print("Key Type:", cert.get_key_type())
print("Key Size:", cert.get_key_size())
print("Key Curve:", cert.get_key_curve())

```

### X.509 CRL

### Loaders
```python
from wrapper.x509 import CRL

# Loading from PEM format file
crl = CRL.load_der_file("crl.pem")

# Loading from DER format file
crl = CRL.load_pem_file("crl.der")

# Loading from PEM base64 string
b64 = "MIIDSzCCAbM....."
crl = CRL.load_base64(b64)
```

### Getters
```python
print("IssuerDN:", crl.get_issuer_dn())
print("Signature algorithm:", crl.get_signature_algorithm())
print("Authority Key Identifier:", crl.get_aki())
print("CRL number:", crl.get_crl_number())

# Delta CRL getters
print("Delta CRL indicator:", crl.is_delta_crl())
print("Delta CRL number:", crl.get_delta_number())

# Entry getters

# Serial number as HEX string
entry = crl.get_entry("E01926C0C94B92D8F8199F558091DC9F349E6B25")
# Serial number as big integer
entry = crl.get_entry(1279374827163150402555346875025145791019302677285)

print("CRL entry reason:", entry.get_reason())
print("CRL entry revocation date:", entry.get_revocation_date())
print("CRL entry invalidity date:", entry.get_invalidity_date())
```

### X.509 CSR

### Loaders

```python
from wrapper.x509 import CSR

# Loading from PEM format file
csr = CSR.load_der_file("csr.pem")

# Loading from DER format file
csr = CSR.load_pem_file("csr.der")

# Loading from PEM base64 string
b64 = "MIIDSzCCAbM....."
csr = CSR.load_base64(b64)
```

### Getters

```python
print("SubjectDN:", csr.get_subject_dn())
print("Subject Alternative Name:", csr.get_san())
print("Signature algorithm:", csr.get_signature_algorithm())

print("Key Type:", csr.get_key_type())
print("Key Size:", csr.get_key_size())
print("Key Curve:", csr.get_key_curve())
```

### Constructor
```python
from wrapper.x509 import RDN
from cryptography.hazmat.primitives.asymmetric import ec

CSR.generate(
    file_csr="rsa.csr", file_key="rsa.key", \
    key_type='RSA', key_size=3072, \
    CN='test', OU='Unit', O='Example', C='FR'
)

CSR.generate(
    file_csr="ecdsa.csr", file_key="ecdsa.key", \
    key_type='ECDSA', key_curve=ec.SECP256R1, CN='test',\
    DNS=['www.test.com', 'www.test.org'], Email=['test@email.com'], \
    IP=['127.0.0.1'], RegID['1.2.3.4']
)

names = {
    RDN.CommonName: "Test",
    RDN.BusinessCategory: 'Business Category',
    RDN.DNQualifier: 'DN Qualifier',
    RDN.Generation: 'Generation Qualifier',
    RDN.GivenName: 'Given Name',
    RDN.Initials: 'Initials',
}
CSR.generate(
    file_csr="rdn.csr", file_key="rdn.key", \
    key_type='RSA', key_size=3072, \
    Names=names,
)
```

### Keys

### Loaders
```python
from wrapper.x509 import KEY

# Loading private key from PEM format file
key = KEY.load_private_key_pem_file("files/file.key")

# Loading private key from DER format file
key = KEY.load_private_key_der_file("files/file.key")

# Loading private key from PEM base64 string
b64 = "MIIG4wIBAAKC......"
key = KEY.load_private_key_base64(b64)

# Loading public key from PEM format file
key = KEY.load_public_key_pem_file("files/file.key")

# Loading public key from DER format file
key = KEY.load_public_key_der_file("files/file.key")

# Loading public key from PEM base64 string
b64 = "MIIBojANBg......."
key = KEY.load_public_key_base64(b64)
```

### Getters
```python
print("Key Type:", key.get_type())
print("Key Size:", key.get_size())
print("Key Curve:", key.get_curve())
print("Key Digest:", key.get_digest())
```
