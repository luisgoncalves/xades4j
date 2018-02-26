========= Description =========

A set of test CRLs and certificates from http://csrc.nist.gov.

Certificate path: Trust Anchor CP.01.01 > Intermediate Certificate 1 CP.02.01 > Intermediate Certificate 2 CP.02.01 > End Certificate CP.02.01.

Contains a PKCS#12 keystore ("test4.p12") with the primate key corresponding to the end certificate.

Added a Java KeyStore ("trustAnchor") for trust anchors, with the certificates from:

	- Trust Anchor CP.01.01
	- ACCV CA, for the TSA certificate - it's on Windows-ROOT, but this way one can use "trustAnchor"


More info on the test certificates: http://csrc.nist.gov/groups/ST/crypto_apps_infra/documents/PKI%20Testing%20Page.htm


======== Trust-anchors keystore =========

keytool -importcert -alias TACP0101 -file "Trust Anchor CP.01.01.crt" -keystore trustAnchor -storepass password

keytool -importcert -alias accvCA -file "..\gva\accvroot1.cer" -keystore trustAnchor -storepass password
