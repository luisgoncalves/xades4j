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
import java.util.Arrays;
import java.util.Collection;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
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
@RunWith(Parameterized.class)
public class SignerEPESTest extends SignerTestBase
{
    @Parameter(0)
    public String locationUrl;
    @Parameter(1)
    public String output;

    @Parameters
    public static Collection<Object[]> data() {
        Object[][] data = new Object[][] { 
            { "http://www.example.com/policy", "document.signed.epes_1.xml" },
            { null, "document.signed.epes_2.xml" }};
        return Arrays.asList(data);
    }

    @Test
    public void testSignEPES() throws Exception
    {
        System.out.printf("signEPES: %s", locationUrl);
        System.out.println();

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();
        
        SignaturePolicyInfoProvider policyInfoProvider = new SignaturePolicyInfoProvider()
        {
            @Override
            public SignaturePolicyBase getSignaturePolicy()
            {
                return new SignaturePolicyIdentifierProperty(
                        new ObjectIdentifier("oid:/1.2.4.0.9.4.5", IdentifierType.OIDAsURI, "Policy description"),
                        new ByteArrayInputStream("Test policy input stream".getBytes()))
                    .withLocationUrl(locationUrl);
            }
        };

        SignerEPES signer = (SignerEPES) new XadesEpesSigningProfile(keyingProviderMy, policyInfoProvider).newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, output);
    }
}
