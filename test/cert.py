from X509_wrapper import Certificate

cert = Certificate.load_der_file("files/ecdsa.crt")
"""
# or
cert = Certificate.load_pem_file("files/ecdsa.pem")
# or
b64 = "MIIFtDCCBBygAwIBAgIUHOB38XG9kbXrFcZdRPv/t930pCIwDQYJKoZIhvcNAQELBQAwJzEQMA4GA1UECgwHQ29tcGFueTETMBEGA1UEAwwKRXhhbXBsZSBDQTAeFw0yMzA0MjgxNjA4MTBaFw0zMzA0MjgxNDIwMzlaMD0xCzAJBgNVBAYTAkZSMRAwDgYDVQQKDAdDb21wYW55MQ0wCwYDVQQLDARVbml0MQ0wCwYDVQQDDAR1c2VyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe46OCAwswggMHMB0GA1UdDgQWBBTdc0FYJUsricMg3iWZF47m/miucDAfBgNVHSMEGDAWgBTG/fjDDPckIkxn9USfO1maN1PvVjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwQQYDVR0fBDowODAaoBigFoYUaHR0cDovL2xvY2FsaG9zdC9jcmwwGqAYoBaGFGxkYXA6Ly9sb2NhbGhvc3QvY3JsMEUGA1UdLgQ+MDwwHKAaoBiGFmh0dHA6Ly9sb2NhbGhvc3QvZGVsdGEwHKAaoBiGFmxkYXA6Ly9sb2NhbGhvc3QvZGVsdGEwgeIGA1UdEQSB2jCB14IPd3d3LmV4YW1wbGUuY29thwR/AAABiAMqAwSBEWVtYWlsQGV4YW1wbGUuY29toB8GCisGAQQBgjcUAgOgEQwPdXBuQGV4YW1wbGUuY29tpDkwNzEUMBIGCgmSJomT8ixkARkWBExEQVAxEDAOBgNVBAoMB0V4YW1wbGUxDTALBgNVBAMMBHVzZXKgHwYJKwYBBAGCNxkBoBIEEKxLKQaq1l1PqZxMvLBqZdmgKQYIKwYBBQUHCAmgHQwbc210cFVURjhNYWlsYm94QGV4YW1wbGUuY29tMBwGA1UdEgQVMBOBEWFkbWluQGV4YW1wbGUuY29tMIGUBgNVHSAEgYwwgYkwUgYMKwYBBAGwLQUBAQEBMEIwIQYIKwYBBQUHAgEWFWh0dHA6Ly9sb2NhbGhvc3QvY3NwMTAdBggrBgEFBQcCAjARMAoMA29yZzADAgEBDAN0eHQwMwYMKwYBBAGwLQUBAQECMCMwIQYIKwYBBQUHAgEWFWh0dHA6Ly9sb2NhbGhvc3QvY3BzMjAoBgkrBgEEAYI3GQIEGzAZoBcGCisGAQQBgjcZAgGgCQQHUy0xLTUtMzBSBggrBgEFBQcBAQRGMEQwIQYIKwYBBQUHMAGGFWh0dHA6Ly9sb2NhbGhvc3Qvb2NzcDAfBggrBgEFBQcwAoYTaHR0cDovL2xvY2FsaG9zdC9jYTANBgkqhkiG9w0BAQsFAAOCAYEAMc/ivcwXqkJ/TSEZJG76Io+7qs45wffkSsyD6EFMIFixa2Zp7tB8RQWNfnQUpOBnpMOC9XSuXaSYGxS2mxWwejDiWB1vtLWqeLYFMILLYNVKlZ85Fc6njJ2YMOnCbrtbfwA6CbIQMK4i178MfE0DSsRL8MRFp4q/MP8lO1W/Pq9z5cEBhuFIMlDvcgGvHkyMlpOw3Hbp99+VKBcAfFpvUDDp1qSZ2VTrjQrbrxXuT7la4fq558XqTCTXwdXyLmUybj7flDjcHyEZdUm72uyRfgS9gbp4D8oTD5dIrWUxBbr7lIofdFvVMsfse9YWiKPuiO40fqiPQnh9Bm4ox7alatac7bPyK0xLr8yFyFrjn6+2Etpyfpz7cdKiLm/amOkC8CsirscMHBZ4OsA6KcLjqFe5RljnPy6Uks7Z3JPVY8lDfRU1+uyKVJwdtrityKxzk/SXfQNXC/x40bbOHdCe9bJo3t5FcrSRMZkJWr2JT0fk/4/35Ylz9qCak50nptE4"
cert = Certificate.load_base64(b64)
"""
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

print("Dump PEM base64:")
print(cert.dump("BASE64"))

print("Dump PEM:")
print(cert.dump("PEM"))
