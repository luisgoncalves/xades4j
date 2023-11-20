/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.providers.impl;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.production.Enveloped;
import xades4j.production.SignerTestBase;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.providers.KeyingDataProvider;
import xades4j.utils.PtCcSigningCertificateSelector;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Luís
 */
class PKCS11KeyStoreKeyingDataProviderTest extends SignerTestBase
{
    @Test
    void testCertAndKeyMatch() throws Exception
    {
        assumePtCcPkcs11();

        KeyingDataProvider ptccKeyingDataProv = PKCS11KeyStoreKeyingDataProvider
                .builder(PTCC_PKCS11_LIB_PATH, new PtCcSigningCertificateSelector())
                .build();

        doTestWithJCA(ptccKeyingDataProv);
        doTestWithXades4j(ptccKeyingDataProv);
    }

    private void doTestWithJCA(KeyingDataProvider keyingDataProvider) throws Exception
    {
        List<X509Certificate> certChain = keyingDataProvider.getSigningCertificateChain();
        assertNotNull(certChain);
        assertEquals(1, certChain.size());

        X509Certificate cert = certChain.get(0);
        PrivateKey key = keyingDataProvider.getSigningKey(cert);

        Signature signatureProdEngine = Signature.getInstance("SHA1with" + key.getAlgorithm());

        signatureProdEngine.initSign(key);
        byte[] signatureData = UUID.randomUUID().toString().getBytes();
        signatureProdEngine.update(signatureData);
        byte[] signatureValue = signatureProdEngine.sign();

        Signature signatureVerifEngine = Signature.getInstance("SHA1with" + key.getAlgorithm());
        signatureVerifEngine.initVerify(cert);
        signatureVerifEngine.update(signatureData);

        assertTrue(signatureVerifEngine.verify(signatureValue));
    }

    private void doTestWithXades4j(KeyingDataProvider keyingDataProvider) throws Exception
    {
        XadesSigner signer = new XadesBesSigningProfile(keyingDataProvider).newSigner();

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();
        new Enveloped(signer).sign(elemToSign);
    }
}
