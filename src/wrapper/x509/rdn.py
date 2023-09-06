from cryptography.hazmat._oid import NameOID
from cryptography.hazmat._oid import ObjectIdentifier


CommonName = NameOID.COMMON_NAME
Country = NameOID.COUNTRY_NAME
Locality = NameOID.LOCALITY_NAME
State = NameOID.STATE_OR_PROVINCE_NAME
StreetAddress = NameOID.STREET_ADDRESS
Organization = NameOID.ORGANIZATION_NAME
OrganizationalUnit = NameOID.ORGANIZATIONAL_UNIT_NAME
Serial = NameOID.SERIAL_NUMBER
Surname = NameOID.SURNAME
GivenName = NameOID.GIVEN_NAME
Title = NameOID.TITLE
Generation = NameOID.GENERATION_QUALIFIER
X500UniqueIdentifier = NameOID.X500_UNIQUE_IDENTIFIER
DNQualifier = NameOID.DN_QUALIFIER
Pseudonym = NameOID.PSEUDONYM
Initials = ObjectIdentifier("2.5.4.43")
UserID = NameOID.USER_ID
DomainComponent = NameOID.DOMAIN_COMPONENT
Email = NameOID.EMAIL_ADDRESS
BusinessCategory = NameOID.BUSINESS_CATEGORY
PostalAddress = NameOID.POSTAL_ADDRESS
PostalCode = NameOID.POSTAL_CODE
