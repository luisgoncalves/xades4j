======== Description ========

Slovakia NATIONAL SECURITY AUTHORITY Root CA 3. Used to verify the SK TSL.

Java keystore ("skStore") with the root certificate so that a cert path can be built.

Policy used in the signature.

=========== Creation of trust-anchors keystore ===========

keytool -importcert -alias skroot -file kcanbusr3_der.cer -keystore skStore -storepass skstorepass
