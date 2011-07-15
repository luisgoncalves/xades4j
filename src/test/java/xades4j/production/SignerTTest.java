/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
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
package xades4j.production;

import com.google.inject.Inject;
import java.security.ProviderException;
import org.junit.Test;
import static org.junit.Assert.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.impl.DefaultTimeStampTokenProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;

/**
 *
 * @author Luís
 */
public class SignerTTest extends SignerTestBase
{
    public static class TestTimeStampTokenProvider extends DefaultTimeStampTokenProvider
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
