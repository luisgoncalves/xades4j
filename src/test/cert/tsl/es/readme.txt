======== Description ========

Certificates in the Spanish Government PKI. Used to verify the ES TSL.

Java keystore ("esStore") with the root certificate so that a cert path can be built.

=========== Creation of trust-anchors keystore ===========

keytool -importcert -alias esroot -file ACRAIZ-SHA1.crt -keystore esStore -storepass esstorepass
