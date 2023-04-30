from X509_wrapper import Certificate

# RSA
cert = Certificate.load_der_file("files/rsa.crt")
cert = Certificate.load_pem_file("files/rsa.pem")
b64 = "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"
cert = Certificate.load_base64(b64)

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
print("Key usage:", cert.get_key_usage())
print("Extended key usage:", cert.get_ext_key_usage())

print("Key Type:", cert.get_key_type())
print("Key Size:", cert.get_key_size())

print("Dump DER:")
print(cert.dump("DER"))

print("Dump PEM base64:")
print(cert.dump("BASE64"))

print("Dump PEM:")
print(cert.dump("PEM"))

# ECDSA
cert = Certificate.load_der_file("files/ecdsa.crt")
cert = Certificate.load_pem_file("files/ecdsa.pem")
b64 = "MIIFtDCCBBygAwIBAgIUHOB38XG9kbXrFcZdRPv/t930pCIwDQYJKoZIhvcNAQELBQAwJzEQMA4GA1UECgwHQ29tcGFueTETMBEGA1UEAwwKRXhhbXBsZSBDQTAeFw0yMzA0MjgxNjA4MTBaFw0zMzA0MjgxNDIwMzlaMD0xCzAJBgNVBAYTAkZSMRAwDgYDVQQKDAdDb21wYW55MQ0wCwYDVQQLDARVbml0MQ0wCwYDVQQDDAR1c2VyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe46OCAwswggMHMB0GA1UdDgQWBBTdc0FYJUsricMg3iWZF47m/miucDAfBgNVHSMEGDAWgBTG/fjDDPckIkxn9USfO1maN1PvVjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwQQYDVR0fBDowODAaoBigFoYUaHR0cDovL2xvY2FsaG9zdC9jcmwwGqAYoBaGFGxkYXA6Ly9sb2NhbGhvc3QvY3JsMEUGA1UdLgQ+MDwwHKAaoBiGFmh0dHA6Ly9sb2NhbGhvc3QvZGVsdGEwHKAaoBiGFmxkYXA6Ly9sb2NhbGhvc3QvZGVsdGEwgeIGA1UdEQSB2jCB14IPd3d3LmV4YW1wbGUuY29thwR/AAABiAMqAwSBEWVtYWlsQGV4YW1wbGUuY29toB8GCisGAQQBgjcUAgOgEQwPdXBuQGV4YW1wbGUuY29tpDkwNzEUMBIGCgmSJomT8ixkARkWBExEQVAxEDAOBgNVBAoMB0V4YW1wbGUxDTALBgNVBAMMBHVzZXKgHwYJKwYBBAGCNxkBoBIEEKxLKQaq1l1PqZxMvLBqZdmgKQYIKwYBBQUHCAmgHQwbc210cFVURjhNYWlsYm94QGV4YW1wbGUuY29tMBwGA1UdEgQVMBOBEWFkbWluQGV4YW1wbGUuY29tMIGUBgNVHSAEgYwwgYkwUgYMKwYBBAGwLQUBAQEBMEIwIQYIKwYBBQUHAgEWFWh0dHA6Ly9sb2NhbGhvc3QvY3NwMTAdBggrBgEFBQcCAjARMAoMA29yZzADAgEBDAN0eHQwMwYMKwYBBAGwLQUBAQECMCMwIQYIKwYBBQUHAgEWFWh0dHA6Ly9sb2NhbGhvc3QvY3BzMjAoBgkrBgEEAYI3GQIEGzAZoBcGCisGAQQBgjcZAgGgCQQHUy0xLTUtMzBSBggrBgEFBQcBAQRGMEQwIQYIKwYBBQUHMAGGFWh0dHA6Ly9sb2NhbGhvc3Qvb2NzcDAfBggrBgEFBQcwAoYTaHR0cDovL2xvY2FsaG9zdC9jYTANBgkqhkiG9w0BAQsFAAOCAYEAMc/ivcwXqkJ/TSEZJG76Io+7qs45wffkSsyD6EFMIFixa2Zp7tB8RQWNfnQUpOBnpMOC9XSuXaSYGxS2mxWwejDiWB1vtLWqeLYFMILLYNVKlZ85Fc6njJ2YMOnCbrtbfwA6CbIQMK4i178MfE0DSsRL8MRFp4q/MP8lO1W/Pq9z5cEBhuFIMlDvcgGvHkyMlpOw3Hbp99+VKBcAfFpvUDDp1qSZ2VTrjQrbrxXuT7la4fq558XqTCTXwdXyLmUybj7flDjcHyEZdUm72uyRfgS9gbp4D8oTD5dIrWUxBbr7lIofdFvVMsfse9YWiKPuiO40fqiPQnh9Bm4ox7alatac7bPyK0xLr8yFyFrjn6+2Etpyfpz7cdKiLm/amOkC8CsirscMHBZ4OsA6KcLjqFe5RljnPy6Uks7Z3JPVY8lDfRU1+uyKVJwdtrityKxzk/SXfQNXC/x40bbOHdCe9bJo3t5FcrSRMZkJWr2JT0fk/4/35Ylz9qCak50nptE4"
cert = Certificate.load_base64(b64)
#cert = Certificate.load_pem_file("files/usage.pem")


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
print("Key usage:", cert.get_key_usage())
print("Extended key usage:", cert.get_ext_key_usage())

print("Key Type:", cert.get_key_type())
print("Key Size:", cert.get_key_size())
print("Key Curve:", cert.get_key_curve())

print("Dump DER:")
print(cert.dump("DER"))

print("Dump PEM base64:")
print(cert.dump("BASE64"))

print("Dump PEM:")
print(cert.dump("PEM"))
