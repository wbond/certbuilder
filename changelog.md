# changelog

## 0.14.1

 - Fix a bug with setting the extended key usage of a CA certificate

## 0.14.0

 - Setting `.ca` to `True` no longer adds the `ocsp_signing` extended key usage
   since the Windows CryptoAPI treats that as a constraint that will be
   propagated down the chain

## 0.13.0

 - Added the `.subject_alt_emails` and `.subject_al_uris` attributes
 - Added explicit support for the TLS Feature extension to `.set_extension()`

## 0.12.1

 - Package metadata updates

## 0.12.0

 - Fix a bug with setting the issuer of a non-self-signed certificate

## 0.11.0

 - Added `pem_armor_certificate()` function
 - Fixed a bug adding subject alt domains/ips

## 0.10.0

 - Removed `CertBuilder.end_entity` attribute, just use `.ca` instead
 - Added Python 2.6 compatbility

## 0.9.0

 - Initial release
