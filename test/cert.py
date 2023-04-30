from X509_wrapper import Certificate

# RSA
cert = Certificate.load_der_file("resources/rsa.crt")
cert = Certificate.load_pem_file("resources/rsa.pem")
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
print("OCSP no check:", cert.get_ocsp_nocheck())
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
cert = Certificate.load_der_file("resources/ecdsa.crt")
cert = Certificate.load_pem_file("resources/ecdsa.pem")
b64 = "MIIFzDCCBDSgAwIBAgIUFkdtoV63MX/ASregpa7Zy5LbZtYwDQYJKoZIhvcNAQELBQAwJzEQMA4GA1UECgwHQ29tcGFueTETMBEGA1UEAwwKRXhhbXBsZSBDQTAeFw0yMzA0MzAxMDMwNTFaFw0zMzA0MjgxNDIwMzlaMD0xCzAJBgNVBAYTAkZSMRAwDgYDVQQKDAdDb21wYW55MQ0wCwYDVQQLDARVbml0MQ0wCwYDVQQDDAR1c2VyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYyYmM/2tiCNLVkJu5tWCvaq4X3hAS6wmwe/a+4NKs/NXAzBa+WKiAYhBwj7VZehu5OCxXVgyPuEQK9uSQTOe46OCAyMwggMfMB0GA1UdDgQWBBTdc0FYJUsricMg3iWZF47m/miucDAfBgNVHSMEGDAWgBTG/fjDDPckIkxn9USfO1maN1PvVjALBgNVHQ8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwQQYDVR0fBDowODAaoBigFoYUaHR0cDovL2xvY2FsaG9zdC9jcmwwGqAYoBaGFGxkYXA6Ly9sb2NhbGhvc3QvY3JsMEUGA1UdLgQ+MDwwHKAaoBiGFmh0dHA6Ly9sb2NhbGhvc3QvZGVsdGEwHKAaoBiGFmxkYXA6Ly9sb2NhbGhvc3QvZGVsdGEwgeUGA1UdEQSB3TCB2oIPd3d3LmV4YW1wbGUuY29thwR/AAABiAMqAwSBEWVtYWlsQGV4YW1wbGUuY29toB8GCisGAQQBgjcUAgOgEQwPdXBuQGV4YW1wbGUuY29tpDwwOjEUMBIGCgmSJomT8ixkARkWBExEQVAxEDAOBgNVBAoMB0V4YW1wbGUxEDAOBgNVBAMMB21hY2hpbmWgHwYJKwYBBAGCNxkBoBIEEKxLKQaq1l1PqZxMvLBqZdmgKQYIKwYBBQUHCAmgHQwbc210cFVURjhNYWlsYm94QGV4YW1wbGUuY29tMBwGA1UdEgQVMBOBEWFkbWluQGV4YW1wbGUuY29tMIGUBgNVHSAEgYwwgYkwUgYMKwYBBAGwLQUBAQEBMEIwIQYIKwYBBQUHAgEWFWh0dHA6Ly9sb2NhbGhvc3QvY3NwMTAdBggrBgEFBQcCAjARMAoMA29yZzADAgEBDAN0eHQwMwYMKwYBBAGwLQUBAQECMCMwIQYIKwYBBQUHAgEWFWh0dHA6Ly9sb2NhbGhvc3QvY3BzMjASBgkrBgEFBQcwAQUBAf8EAgUAMCkGCSsGAQQBgjcZAgQcMBqgGAYKKwYBBAGCNxkCAaAKBAhTLTEtNS00NzBSBggrBgEFBQcBAQRGMEQwIQYIKwYBBQUHMAGGFWh0dHA6Ly9sb2NhbGhvc3Qvb2NzcDAfBggrBgEFBQcwAoYTaHR0cDovL2xvY2FsaG9zdC9jYTANBgkqhkiG9w0BAQsFAAOCAYEAdR3qc+Iq2/cv/hFw2hNG7jN3vw+B38IiSalI0rvYpWJmVne8JR9g7HSD00drU2cTPG0iWNU+GrNND+WW70yhmPNCFIj3KD3SmB9Qks3PwkRaMg/ZqIZkCNNVU9/DolORcVQmig7gFlnzAdybElsbD27NNFonxbGwnbs7SurwLYjLawG/NpvGZGb8HQk9drsl5XzDV1V7bto0ODgnvY/ixvymaHWa4+Ysm6EzImxFbFuDCO2TKmBuP1zuK9QXuo2VbxYRC9yYTMK+YmYR78YQqvozcKHYtvjwjGF4og5lEePbdrj19KZ8CBe8aJyRPz1jxoJ5HnffeMde73AUjjmyarWNn5AMl87Q8vgJR8yZfagHFAdMzUrxUoIXG3p8jUBp9mW59eowT5172016esofi/Jbj1y3tIu7VgD8C1apvVcm9fK/nkdxnT0DIu2OciXxPFaZQZc12o+uIo1R9JGaIPY58cSz9MgND1XVawpL01TDM7gCD1wcM1Eyq/QYB8mw"
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
print("OCSP no check:", cert.get_ocsp_nocheck())
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
