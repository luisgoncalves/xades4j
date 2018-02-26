======== Description ========

Certificate and CRL from ACCV RAIZ 1.

The CRL may need to be updated (http://www.accv.es/ciudadanos/validacion-de-certificados/).

The default TSA is from http://www.accv.es/ and its certificate is issued by the above CA.

======== Trust-anchors keystore =========


keytool -importcert -alias accvCA -file "accvroot1.cer" -keystore trustAnchor -storepass password
