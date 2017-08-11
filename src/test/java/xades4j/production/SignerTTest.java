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
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.HttpTimeStampTokenProvider;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.providers.impl.TSAHttpData;

/**
 *
 * @author Luís
 */
public class SignerTTest extends SignerTestBase
{
    static class TestTimeStampTokenProvider extends HttpTimeStampTokenProvider
    {
        @Inject
        public TestTimeStampTokenProvider(MessageDigestEngineProvider messageDigestProvider)
        {
            super(messageDigestProvider, new TSAHttpData("http://tsa.starfieldtech.com"));
        }
    }

    static class ExclusiveC14nForTimeStampsAlgorithmsProvider extends DefaultAlgorithmsProviderEx
    {
        @Override
        public Algorithm getCanonicalizationAlgorithmForTimeStampProperties()
        {
            return new ExclusiveCanonicalXMLWithoutComments("ds", "xades");
        }

        @Override
        public Algorithm getCanonicalizationAlgorithmForSignature()
        {
            return new ExclusiveCanonicalXMLWithoutComments();
        }
    }

    @Test
    public void testSignTExclusiveC14NWithoutPolicy() throws Exception
    {
        System.out.println("signTExclusiveC14NWithoutPolicy");

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        SignerT signer = (SignerT) new XadesTSigningProfile(keyingProviderMy)
                .withTimeStampTokenProvider(TestTimeStampTokenProvider.class)
                .withAlgorithmsProviderEx(ExclusiveC14nForTimeStampsAlgorithmsProvider.class)
                .newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.t.bes.xml");
    }

    @Test
    public void testSignTWithPolicy() throws Exception
    {
        System.out.println("signTWithPolicy");

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        SignerT signer = (SignerT) new XadesTSigningProfile(keyingProviderMy).withPolicyProvider(new SignaturePolicyInfoProvider()
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
        assumePtCcPkcs11OnWindows();

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        PKCS11KeyStoreKeyingDataProvider ptccKeyingDataProv = new PKCS11KeyStoreKeyingDataProvider(
                PTCC_PKCS11_LIB_PATH, "PT_CC",
                new FirstCertificateSelector(), null, null, false);

        SignerT signer = (SignerT) new XadesTSigningProfile(ptccKeyingDataProv).withAlgorithmsProviderEx(PtCcAlgorithmsProvider.class).newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.t.bes.ptcc.xml");
    }
}
