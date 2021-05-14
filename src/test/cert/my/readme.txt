========== Description ==========

Keys and certificates generated with makecert. Certification path: TestCA > Interm > LG

Java keystore ("myStore") for trust-anchors, with the certificates from:

	- TestCA
	- ACCV CA, for TSA certificate - it's on Windows-ROOT, but this way one can use "mystore"
	- Starfield Class 2 Certification Authority, for TSA certificate


PKCS#12 keystore ("LG.pfx") for the private key: LG.pvk/LG.cer


========== Generation of keys and certificates ===========

key and pfx password: mykeypass

makecert -n "CN=TestCA, OU=CC, O=ISEL, C=PT" -r -a sha1 -sv TestCA.pvk TestCA.cer
makecert -sv Interm.pvk -cy authority -iv TestCA.pvk -ic TestCA.cer -n "CN=Itermediate, OU=CC, O=ISEL, C=PT" -a sha1 Interm.cer
makecert -sv LG.pvk -iv Interm.pvk -ic Interm.cer -n "CN=Luis Goncalves, OU=CC, O=ISEL, C=PT" -a sha1 LG.cer
pvk2pfx.exe -pvk LG.pvk -pi mykeypass -spc LG.cer -pfx LG.pfx

openssl ecparam -out lg_ec.key -name prime256v1 -genkey
openssl req -new -x509 -key lg_ec.key -out lg_ec.crt -days 3650
openssl pkcs12 -export -in lg_ec.crt -inkey lg_ec.key -out lg_ec.p12 -name lg_ec

=========== Creation of trust-anchors keystore ===========

--> Test CA

	keytool -importcert -alias testCA -file TestCA.cer -keystore myStore -storepass mystorepass

--> ACCV CA for the TSA certificate 

	keytool -importcert -alias accvCA -file "..\gva\accvroot1.cer" -keystore myStore -storepass mystorepass

--> Starfield Class 2 Certification Authority

	keytool -importcert -alias sfCA -file "..\starfield\sf-class2-root.cer" -keystore myStore -storepass mystorepass