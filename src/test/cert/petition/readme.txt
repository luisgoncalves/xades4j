======== Description ========

Certificates in the Portuguese Government PKI and top most CA which is "GTE CyberTrust Global Root".

Used to verify a signature produced by SignIt, a project from another student at ISEL (Projecto e Seminário 2009/2010). The signature is a XAdES-T, using http://tsp.iaik.at/tsp/.

=========== Creation of trust-anchors keystore ===========

--> CyberTrust CA

	keytool -importcert -alias cybertrus -file CyberTrust.cer -keystore signitStore -storepass signitstorepass

--> TSA certificate 

	keytool -importcert -alias iaikTSA -file "IAIKtsaCert.cer" -keystore signitStore -storepass signitstorepass
