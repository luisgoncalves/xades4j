/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.properties.DataObjectDesc;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class OtherSignerTests extends SignerTestBase
{

    @Test
    public void testSignAndAppendAsFirstChild() throws Exception
    {
        System.out.println("signAndAppendAsFirstChild");

        Document doc = getTestDocument();
        Element root = doc.getDocumentElement();
        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMy).newSigner();

        DataObjectDesc obj1 = new DataObjectReference('#' + root.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects dataObjs = new SignedDataObjects(obj1);

        signer.sign(dataObjs, root, SignatureAppendingStrategies.AsFirstChild);

        Element firstChild = (Element) doc.getDocumentElement().getFirstChild();
        assertEquals(Constants._TAG_SIGNATURE, firstChild.getLocalName());
        assertEquals(Constants.SignatureSpecNS, firstChild.getNamespaceURI());
    }

    @Test
    public void testSignUsingCustomResolver() throws Exception
    {
        System.out.println("signUsingCustomResolver");

        Document doc = getNewDocument();
        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMy).newSigner();
        MyResolverSpi resolverSpi = new MyResolverSpi();

        SignedDataObjects dataObjs = new SignedDataObjects()
                .withSignedDataObject(new DataObjectReference("xades4j://ref"))
                .withResourceResolver(new ResourceResolver(resolverSpi));

        signer.sign(dataObjs, doc);

        assertEquals(1, resolverSpi.resolveCount);
    }

    class MyResolverSpi extends ResourceResolverSpi
    {
        private int resolveCount = 0;

        @Override
        public XMLSignatureInput engineResolve(Attr attr, String baseUri) throws ResourceResolverException
        {
            XMLSignatureInput input = new XMLSignatureInput(attr.getValue().getBytes());
            resolveCount++;
            return input;
        }

        @Override
        public boolean engineCanResolve(Attr attr, String baseUri)
        {
            return attr.getValue().startsWith("xades4j:");
        }
    }
}
