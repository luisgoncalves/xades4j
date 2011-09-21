======== Description ========

Certificates in the Italian Government PKI. Used to verify the IT TSL.

https://applicazioni.cnipa.gov.it/TSL/IT_TSL.zip

Java keystore ("itStore") with the root certificate so that a cert path can be built.

=========== Creation of trust-anchors keystore ===========

keytool -importcert -alias itroot -file DigitPA.cer -keystore itStore -storepass itstorepass
