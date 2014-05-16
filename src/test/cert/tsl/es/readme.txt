======== Description ========

Certificates in the Spanish Government PKI. Used to verify the ES TSL (http://www.minetur.gob.es/telecomunicaciones/es-ES/Servicios/FirmaElectronica/Paginas/Prestadores.aspx).

Java keystore ("esStore") with the root certificate so that a cert path can be built.

=========== Creation of trust-anchors keystore ===========

keytool -importcert -alias esroot -file TSL_OPERATOR.cer -keystore esStore -storepass esstorepass
