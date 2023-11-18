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
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.QualifyingProperty;
import xades4j.providers.ValidationDataProvider;
import xades4j.providers.impl.ValidationDataFromCertValidationProvider;
import xades4j.verification.VerifierTestBase;

import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.util.Iterator;

import static org.apache.xml.security.algorithms.MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
import static org.apache.xml.security.algorithms.MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
import static org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
import static org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
import static org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;
import static org.apache.xml.security.utils.Constants.SignatureSpecNS;
import static org.apache.xml.security.utils.Constants._TAG_SIGNATURE;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Luís
 */
class OtherSignerTests extends SignerTestBase
{
    @Test
    void testSignAndAppendAsFirstChild() throws Exception
    {
        Document doc = getTestDocument();
        Element root = doc.getDocumentElement();
        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMy).newSigner();

        DataObjectDesc obj1 = new DataObjectReference('#' + root.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects dataObjs = new SignedDataObjects(obj1);

        signer.sign(dataObjs, root, SignatureAppendingStrategies.AsFirstChild);

        Element firstChild = (Element) doc.getDocumentElement().getFirstChild();
        assertEquals(_TAG_SIGNATURE, firstChild.getLocalName());
        assertEquals(SignatureSpecNS, firstChild.getNamespaceURI());
    }

    @Test
    void testSignWithManifest() throws Exception
    {
        Document doc = getTestDocument();
        Element root = doc.getDocumentElement();
        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMy).newSigner();

        DataObjectDesc obj1 = new EnvelopedManifest()
                .withSignedDataObject(new DataObjectReference("#" + root.getAttribute("Id"))
                        .withTransform(new EnvelopedSignatureTransform()))
                .withSignedDataObject(new EnvelopedXmlObject(doc.createTextNode("DATA")));
        signer.sign(new SignedDataObjects(obj1), root);

        outputDocument(doc, "document.signed.bes.manifest.xml");
    }

    @Test
    void testSignUsingCustomResolver() throws Exception
    {
        Document doc = getNewDocument();
        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMy).newSigner();
        MyResolverSpi resolverSpi = new MyResolverSpi();

        SignedDataObjects dataObjs = new SignedDataObjects()
                .withSignedDataObject(new DataObjectReference("xades4j://ref"))
                .withResourceResolver(resolverSpi);

        signer.sign(dataObjs, doc);

        assertEquals(1, resolverSpi.resolveCount);
    }

    static class MyResolverSpi extends ResourceResolverSpi
    {
        private int resolveCount = 0;

        @Override
        public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException
        {
            XMLSignatureInput input = new XMLSignatureInput(context.attr.getValue().getBytes());
            resolveCount++;
            return input;
        }

        @Override
        public boolean engineCanResolveURI(ResourceResolverContext context)
        {
            return context.uriToResolve.startsWith("xades4j:");
        }
    }

    @Test
    void testSignatureAlgorithms() throws Exception
    {
        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        ValidationDataProvider vdp = new ValidationDataFromCertValidationProvider(VerifierTestBase.validationProviderNist);
        XadesSigner signer = new XadesCSigningProfile(keyingProviderNist, vdp)
                .withSignatureAlgorithms(new SignatureAlgorithms()
                        .withSignatureAlgorithm("RSA", ALGO_ID_SIGNATURE_RSA_SHA512)
                        .withCanonicalizationAlgorithmForTimeStampProperties(new ExclusiveCanonicalXMLWithoutComments())
                        .withDigestAlgorithmForReferenceProperties(ALGO_ID_DIGEST_SHA512))
                .with(DEFAULT_TEST_TSA)
                .newSigner();
        new Enveloped(signer).sign(elemToSign);

        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(new TestNamespaceContext());

        var signatureC14n = (Attr) xpath.evaluate("//ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm", doc, XPathConstants.NODE);
        assertEquals(ALGO_ID_C14N_OMIT_COMMENTS, signatureC14n.getValue());

        var signature = (Attr) xpath.evaluate("//ds:SignedInfo/ds:SignatureMethod/@Algorithm", doc, XPathConstants.NODE);
        assertEquals(ALGO_ID_SIGNATURE_RSA_SHA512, signature.getValue());

        var referenceDigest = (Attr) xpath.evaluate("//ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm", doc, XPathConstants.NODE);
        assertEquals(ALGO_ID_DIGEST_SHA256, referenceDigest.getValue());

        var tsC14n = (Attr) xpath.evaluate("//xades:UnsignedSignatureProperties/xades:SignatureTimeStamp/ds:CanonicalizationMethod/@Algorithm", doc, XPathConstants.NODE);
        assertEquals(ALGO_ID_C14N_EXCL_OMIT_COMMENTS, tsC14n.getValue());

        var certReferenceDigest = (Attr) xpath.evaluate("//xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs/xades:CertRefs/xades:Cert/xades:CertDigest/ds:DigestMethod/@Algorithm", doc, XPathConstants.NODE);
        assertEquals(ALGO_ID_DIGEST_SHA512, certReferenceDigest.getValue());
    }

    private static final class TestNamespaceContext implements NamespaceContext
    {
        @Override
        public String getNamespaceURI(String prefix)
        {
            switch (prefix)
            {
                case "ds":
                    return SignatureSpecNS;
                case "xades":
                    return QualifyingProperty.XADES_XMLNS;
                case "xades141":
                    return QualifyingProperty.XADESV141_XMLNS;
            }
            return null;
        }

        @Override
        public String getPrefix(String namespaceURI)
        {
            return null;
        }

        @Override
        public Iterator<String> getPrefixes(String namespaceURI)
        {
            return null;
        }
    }
}
