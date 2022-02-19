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

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.impl.HttpTsaConfiguration;

/**
 * @author Luís
 */
public class SignerTTest extends SignerTestBase
{
    @Test
    public void testSignTExclusiveC14NWithoutPolicy() throws Exception
    {
        System.out.println("signTExclusiveC14NWithoutPolicy");

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        SignatureAlgorithms algorithms = new SignatureAlgorithms()
                .withCanonicalizationAlgorithmForTimeStampProperties(new ExclusiveCanonicalXMLWithoutComments("ds", "xades"))
                .withCanonicalizationAlgorithmForSignature(new ExclusiveCanonicalXMLWithoutComments());

        XadesSigner signer = new XadesTSigningProfile(keyingProviderMy)
                .withSignatureAlgorithms(algorithms)
                .with(new HttpTsaConfiguration("http://timestamp.digicert.com"))
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

        XadesSigner signer = new XadesTSigningProfile(keyingProviderMy)
                .withPolicyProvider(new SignaturePolicyInfoProvider()
                {
                    @Override
                    public SignaturePolicyBase getSignaturePolicy()
                    {
                        return new SignaturePolicyImpliedProperty();
                    }
                })
                .with(DEFAULT_TEST_TSA)
                .newSigner();

        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.t.epes.xml");
    }
}
