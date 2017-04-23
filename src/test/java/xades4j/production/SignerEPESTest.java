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

import java.io.ByteArrayInputStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.properties.IdentifierType;
import xades4j.properties.ObjectIdentifier;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.providers.SignaturePolicyInfoProvider;

/**
 *
 * @author Luís
 */
public class SignerEPESTest extends SignerTestBase
{
    private SignaturePolicyInfoProvider policyInfoProvider;

    @Before
    public void setUp() throws Exception
    {
        policyInfoProvider = new SignaturePolicyInfoProvider()
        {
            @Override
            public SignaturePolicyBase getSignaturePolicy()
            {
                return new SignaturePolicyIdentifierProperty(
                        new ObjectIdentifier("oid:/1.2.4.0.9.4.5", IdentifierType.OIDAsURI, "Policy description"),
                        new ByteArrayInputStream("Test policy input stream".getBytes()))
                    .withLocationUrl("http://www.example.com/policy");
            }
        };
    }

    @After
    public void tearDown()
    {
    }

    @Test
    public void testSignEPES() throws Exception
    {
        System.out.println("signEPES");

        Document doc = getTestDocument();

        Element elemToSign = doc.getDocumentElement();

        SignerEPES signer = (SignerEPES)new XadesEpesSigningProfile(keyingProviderMy, policyInfoProvider).newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.epes.xml");
    }
}
