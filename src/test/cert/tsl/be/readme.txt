========== Description ==========

Self-signed certificate for the Belgian Trust List Scheme Operator. Used to verify the BE TSL.

Java keystore ("beStore") with the above certificate so that a cert path can be built.

=========== Creation of trust-anchors keystore ===========

keytool -importcert -alias beTLSO -file be_tlso.cer -keystore beStore -storepass bestorepass