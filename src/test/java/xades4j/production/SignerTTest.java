/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.production;

import com.google.inject.Inject;
import java.security.ProviderException;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.Test;
import static org.junit.Assert.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.impl.DefaultAlgorithmsProvider;
import xades4j.providers.impl.DefaultTimeStampTokenProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;

/**
 *
 * @author Luís
 */
public class SignerTTest extends SignerTestBase
{
    static class TestTimeStampTokenProvider extends DefaultTimeStampTokenProvider
    {
        @Inject
        public TestTimeStampTokenProvider(
                MessageDigestEngineProvider messageDigestProvider)
        {
            super(messageDigestProvider);
        }

        @Override
        protected String getTSAUrl()
        {
            return "http://tsa.starfieldtech.com/";
        }
    }

    static class PtCcAlgorithmsProvider extends DefaultAlgorithmsProvider
    {
        @Override
        public String getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException
        {
            // The test card didn't support RSA_SHA_256.
            return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
        }
    }

    @Test
    public void testSignTWithoutPolicy() throws Exception
    {
        System.out.println("signTWithoutPolicy");

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        SignerT signer = (SignerT)new XadesTSigningProfile(keyingProviderMy).withTimeStampTokenProvider(TestTimeStampTokenProvider.class).newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.t.bes.xml");
    }

    @Test
    public void testSignTWithPolicy() throws Exception
    {
        System.out.println("signTWithPolicy");

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        SignerT signer = (SignerT)new XadesTSigningProfile(keyingProviderMy).withPolicyProvider(new SignaturePolicyInfoProvider()
        {
            @Override
            public SignaturePolicyBase getSignaturePolicy()
            {
                return new SignaturePolicyImpliedProperty();
            }
        }).newSigner();

        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.t.epes.xml");
    }

    @Test
    public void testSignTPtCC() throws Exception
    {
        System.out.println("signTPtCitizenCard");

        if (!onWindowsPlatform())
            fail("Test written for the Windows platform");

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();
        try
        {
            PKCS11KeyStoreKeyingDataProvider ptccKeyingDataProv = new PKCS11KeyStoreKeyingDataProvider(
                    "C:\\Windows\\System32\\pteidpkcs11.dll", "PT_CC",
                    new FirstCertificateSelector(), null, null, false);

            SignerT signer = (SignerT)new XadesTSigningProfile(ptccKeyingDataProv).withAlgorithmsProvider(PtCcAlgorithmsProvider.class).newSigner();
            new Enveloped(signer).sign(elemToSign);

            outputDocument(doc, "document.signed.t.bes.ptcc.xml");
        } catch (ProviderException ex)
        {
            fail("PT CC PKCS#11 provider not configured");
        }
    }
}
