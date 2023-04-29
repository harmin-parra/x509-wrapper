# X509 Wrapper

`X509_wraper` is a wrapper for the [pyca/cryptography](https://cryptography.io/en/latest/) package.

It allows to query X509 chryptography object attributes in a fast and easy way.

The attribute values are returned as Python primitive and built-in types (`integer`, `string`, `boolean` and `lists`) instead of being returned as  instances of `pyca/cryptography` classes like `cryptography.x509.Name`, `cryptography.x509.GeneralName`, `cryptography.x509.AuthorityKeyIdentifier`, `cryptography.x509.CRLDistributionPoints`, `cryptography.x509.Extension`, etc.

## Supported X509 cryptography objects
- Certificate
- Certificate revocation list (CRL)
- Delta certificate revocationlist (Delta CRL)
- Certificate signing request (CSR)
- RSA / ECDSA public and private key

## Limitations
### Construction/Generation of CSR*

+ Only the following relative distinguished names (RDN) are supported:
  + CN (common name)
  + OU (organizaion unit)
  + O  (organization)
  + C  (country code)

+ Subject Directory Names (SAN) of the following types are not supported:
  + Directory Name
  + Other Name

*issues don't apply to CSR loaders

### Loading of ECDSA private and public keys

`pyca/cryptography` doesn't support ECDSA keys with explicit parameters [#7339](https://github.com/pyca/cryptography/issues/7339).
Therefore, loading ECDSA from base64 strings are not supported.

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

### X509 CRL

### Loaders
```python
from X509_wrapper import CRL

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
print("CRL entry invalidity date:", entry.get_invalidity_date())
```

### X509 CSR

### Loaders

```python
from X509_wrapper import CSR

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
print("Subject Alternative Name:", csr.get_san_list())
print("Signature algorithm:", csr.get_signature_algorithm())

print("Key Type:", csr.get_key_type())
print("Key Size:", csr.get_key_size())
print("Key Curve:", csr.get_key_curve())
```

### Constructor
```python
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
```
