from X509_wrapper import CRL

# CRL
crl = CRL.load_der_file("resources/crl.der")
crl = CRL.load_pem_file("resources/crl.pem")
b64 = "MIIDSzCCAbMCAQEwDQYJKoZIhvcNAQELBQAwJjEPMA0GA1UECgwGSUQgUEtJMRMwEQYDVQQDDApJc3N1aW5nIENBFw0yMjA4MjAxMDA2MDJaFw0yMzA4MjAxMDA2MDJaMIIBJjA0AhUA36b291fmXjUFO307zn0mUXKJFa8XDTIyMDgwMTA5NTkyNVowDDAKBgNVHRUEAwoBBjAlAhRq+qpUJEfKonL6t8h9wwMStdjZoBcNMjIwODAyMTAwMTAxWjAzAhQcJa1u/0hRzzGeR9aK9sLbMAt6XRcNMjIwODAzMTAwMTI2WjAMMAoGA1UdFQQDCgEFME4CFQDgGSbAyUuS2PgZn1WAkdyfNJ5rJRcNMjIwODA0MTAwMTQzWjAmMAoGA1UdFQQDCgEEMBgGA1UdGAQRGA8yMDIwMDcwMzIzMDAwMFowQgIVAK6YZOoHk+k6PCa0j3/hLhZ79krDFw0yMjA4MDUxMDAxNTFaMBowGAYDVR0YBBEYDzIwMjAwNzA0MjMwMDAwWqAvMC0wCgYDVR0UBAMCAQUwHwYDVR0jBBgwFoAUiSHVAoKdwFixhxnibbS6Fnt0bXMwDQYJKoZIhvcNAQELBQADggGBAK8QAGZFNv1EFj/HICYNCSZXFwB13L7o5SAf0C/V3ueA5414FgErLDW3mL2pWgi+v3NyIv/vjcJGJprZbj6FZbM3D+K9JleocEtwETHGGmeGIo5XIZUNiMP6ZTtuccz6jwCW46LlFfd0qUCje8h6FcQCOAGKX9jdTwKjGvVLvPKbDKHyELl1QK1ctb1LCHQVQimBmJ2/AO6/6/iolDkTNCcXVoqT8sHCNp3BGTvbfXERwX6Rgg4AkOmcuGzAEc5+zTdvfvyWAqoo5WO3YTkVsawme9gHlwk/2GCX6tDKtBjycXVp1FpYtqw0KYoVigD4OqZSu6DBfS9VvAYzcFjJ68lFI2QbXXMhE/p/Hbc1f2Qvh7+yzDwWm45LGTh7U/HmvOgNfXE6GpDSCK/Nayn8geYyhDU39OwnxbTRMT4FtqppYA3ZZx60MbfsAdp8PAosI5egy6J5eEGFIgM2bz3yN93sEzfpzPryVm2Ng+/AHGKE87KmhMNPE7dM7b6+mYDfoA=="
#crl = CRL.load_base64(b64)

print("IssuerDN:", crl.get_issuer_dn())
print("Signature algorithm:", crl.get_signature_algorithm())
print("Authority Key Identifier:", crl.get_aki())
print("CRL number:", crl.get_crl_number())
print("Next publish:", crl.get_next_publish())

print("Delta CRL indicator:", crl.is_delta_crl())

print(crl.dump("DER"))
print(crl.dump("BASE64"))
print(crl.dump("PEM"))


# Delta CRL
delta = CRL.load_der_file("resources/delta.der")
delta = CRL.load_pem_file("resources/delta.pem")
b64 = "MIIDSzCCAbMCAQEwDQYJKoZIhvcNAQELBQAwJjEPMA0GA1UECgwGSUQgUEtJMRMwEQYDVQQDDApJc3N1aW5nIENBFw0yMjA4MjAxMDA2MDJaFw0yMzA4MjAxMDA2MDJaMIIBJjA0AhUA36b291fmXjUFO307zn0mUXKJFa8XDTIyMDgwMTA5NTkyNVowDDAKBgNVHRUEAwoBBjAlAhRq+qpUJEfKonL6t8h9wwMStdjZoBcNMjIwODAyMTAwMTAxWjAzAhQcJa1u/0hRzzGeR9aK9sLbMAt6XRcNMjIwODAzMTAwMTI2WjAMMAoGA1UdFQQDCgEFME4CFQDgGSbAyUuS2PgZn1WAkdyfNJ5rJRcNMjIwODA0MTAwMTQzWjAmMAoGA1UdFQQDCgEEMBgGA1UdGAQRGA8yMDIwMDcwMzIzMDAwMFowQgIVAK6YZOoHk+k6PCa0j3/hLhZ79krDFw0yMjA4MDUxMDAxNTFaMBowGAYDVR0YBBEYDzIwMjAwNzA0MjMwMDAwWqAvMC0wCgYDVR0UBAMCAQUwHwYDVR0jBBgwFoAUiSHVAoKdwFixhxnibbS6Fnt0bXMwDQYJKoZIhvcNAQELBQADggGBAK8QAGZFNv1EFj/HICYNCSZXFwB13L7o5SAf0C/V3ueA5414FgErLDW3mL2pWgi+v3NyIv/vjcJGJprZbj6FZbM3D+K9JleocEtwETHGGmeGIo5XIZUNiMP6ZTtuccz6jwCW46LlFfd0qUCje8h6FcQCOAGKX9jdTwKjGvVLvPKbDKHyELl1QK1ctb1LCHQVQimBmJ2/AO6/6/iolDkTNCcXVoqT8sHCNp3BGTvbfXERwX6Rgg4AkOmcuGzAEc5+zTdvfvyWAqoo5WO3YTkVsawme9gHlwk/2GCX6tDKtBjycXVp1FpYtqw0KYoVigD4OqZSu6DBfS9VvAYzcFjJ68lFI2QbXXMhE/p/Hbc1f2Qvh7+yzDwWm45LGTh7U/HmvOgNfXE6GpDSCK/Nayn8geYyhDU39OwnxbTRMT4FtqppYA3ZZx60MbfsAdp8PAosI5egy6J5eEGFIgM2bz3yN93sEzfpzPryVm2Ng+/AHGKE87KmhMNPE7dM7b6+mYDfoA=="
#delta = CRL.load_base64(b64)

print("IssuerDN:", delta.get_issuer_dn())
print("Signature algorithm:", delta.get_signature_algorithm())
print("CRL number:", delta.get_crl_number())
print("Next publish:", crl.get_next_publish())

print("Delta CRL indicator:", delta.is_delta_crl())
print("Delta CRL number:", delta.get_delta_number())

print(delta.dump("DER"))
print(delta.dump("BASE64"))
print(delta.dump("PEM"))

"""
# CRL Entry
serial = "E01926C0C94B92D8F8199F558091DC9F349E6B25"
entry = crl.get_entry(serial)
serial = int('E01926C0C94B92D8F8199F558091DC9F349E6B25', base = 16)
entry = crl.get_entry(serial)
print("Entry reason:", entry.get_reason())

serial = "E01926C0C94B92D8F8199F558091DC9F349E6B25"
entry = crl.get_entry(serial)
serial = int('E01926C0C94B92D8F8199F558091DC9F349E6B25', base = 16)
entry = crl.get_entry(serial)
print("Entry reason:", entry.get_reason())

serial = "E01926C0C94B92D8F8199F558091DC9F349E6B25"
entry = crl.get_entry(serial)
print("Entry reason:", entry.get_reason())
print("Entry invalidity date:", entry.get_invalidity_date())

serial = "E01926C0C94B92D8F8199F558091DC9F349E6B25"
entry = crl.get_entry(serial)
print("Entry reason:", entry.get_reason())
print("Entry invalidity date:", entry.get_invalidity_date())
"""
