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

import xades4j.production.XadesBesSigningProfile;
import org.w3c.dom.Element;
import xades4j.production.SignerTestBase;
import org.w3c.dom.Document;
import xades4j.production.Enveloped;
import xades4j.production.XadesSigner;
import xades4j.production.PtCcAlgorithmsProvider;
import java.security.ProviderException;
import java.util.UUID;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import xades4j.providers.KeyingDataProvider;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class PKCS11KeyStoreKeyingDataProviderTest extends SignerTestBase
{
    private static final int N_RETRIES = 3;

    @Test
    public void testCertAndKeyMatch() throws Exception
    {
        System.out.println("certAndKeyMatch");

        if (!onWindowsPlatform())
        {
            return;
        }

        try
        {
            KeyingDataProvider ptccKeyingDataProv = new PKCS11KeyStoreKeyingDataProvider(
                    "C:\\Windows\\System32\\pteidpkcs11.dll", "PT_CC", new FirstCertificateSelector());
            doTestWithJCA(ptccKeyingDataProv);

            ptccKeyingDataProv = new PKCS11KeyStoreKeyingDataProvider(
                    "C:\\Windows\\System32\\pteidpkcs11.dll", "PT_CC", new FirstCertificateSelector());
            doTestWithXades4j(ptccKeyingDataProv);
        } catch (ProviderException ex)
        {
            fail("PT CC PKCS#11 provider not configured");
        }
    }

    private void doTestWithJCA(KeyingDataProvider keyingDataProvider) throws Exception
    {
        for (int i = 0; i < N_RETRIES; i++)
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
    }

    private void doTestWithXades4j(KeyingDataProvider keyingDataProvider) throws Exception
    {
        XadesSigner signer = new XadesBesSigningProfile(keyingDataProvider).withAlgorithmsProviderEx(PtCcAlgorithmsProvider.class).newSigner();

        for (int i = 0; i < N_RETRIES; i++)
        {
            Document doc = getTestDocument();
            Element elemToSign = doc.getDocumentElement();
            new Enveloped(signer).sign(elemToSign);
        }
    }
}
