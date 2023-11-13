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

import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureStreamInput;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.utils.DOMHelper;
import xades4j.utils.SignatureServicesTestBase;
import xades4j.utils.StringUtils;

import java.io.ByteArrayInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Luís
 */
public class SignedDataObjectsProcessorTest extends SignatureServicesTestBase
{
    @BeforeAll
    public static void setUpClass()
    {
        Init.initXMLSec();
    }

    @Test
    void testProcess() throws Exception
    {
        Document doc = getNewDocument();

        SignedDataObjects dataObjsDescs = new SignedDataObjects()
                .withSignedDataObject(new DataObjectReference("uri").withTransform(new EnvelopedSignatureTransform()))
                .withSignedDataObject(new EnvelopedXmlObject(doc.createElement("test1")))
                .withSignedDataObject(new EnvelopedXmlObject(doc.createElement("test2"), "text/xml", null));

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        AllwaysNullAlgsParamsMarshaller algsParamsMarshaller = new AllwaysNullAlgsParamsMarshaller();

        SignedDataObjectsProcessor processor = new SignedDataObjectsProcessor(new SignatureAlgorithms(), algsParamsMarshaller);
        SignedDataObjectsProcessor.Result result = processor.process(dataObjsDescs, xmlSignature);

        assertEquals(3, result.referenceMappings.size());
        assertEquals(3, xmlSignature.getSignedInfo().getLength());
        assertEquals(2, xmlSignature.getObjectLength());

        assertEquals(1, algsParamsMarshaller.getInvokeCount());

        Reference ref = xmlSignature.getSignedInfo().item(0);
        assertEquals("sigId-ref0", ref.getId());
        assertEquals("uri", ref.getURI());
        assertEquals(1, ref.getTransforms().getLength());

        ref = xmlSignature.getSignedInfo().item(1);
        assertEquals("sigId-ref1", ref.getId());
        assertEquals("#sigId-object1", ref.getURI());
        assertNull(ref.getTransforms());

        ObjectContainer obj = xmlSignature.getObjectItem(0);
        assertEquals("sigId-object1", obj.getId());
        assertTrue(StringUtils.isNullOrEmptyString(obj.getMimeType()));
        assertTrue(StringUtils.isNullOrEmptyString(obj.getEncoding()));

        ref = xmlSignature.getSignedInfo().item(2);
        assertEquals("sigId-ref2", ref.getId());
        assertEquals("#sigId-object2", ref.getURI());
        assertNull(ref.getTransforms());

        obj = xmlSignature.getObjectItem(1);
        assertEquals("sigId-object2", obj.getId());
        assertEquals("text/xml", obj.getMimeType());
        assertTrue(StringUtils.isNullOrEmptyString(obj.getEncoding()));
    }

    @Test
    void testAddManifest() throws Exception
    {
        Document doc = getNewDocument();

        SignedDataObjects signedObjects = new SignedDataObjects()
                .withSignedDataObject(new EnvelopedManifest()
                        .withSignedDataObject(new DataObjectReference("xades4j:1"))
                        .withSignedDataObject(new DataObjectReference("xades4j:2"))
                        .withSignedDataObject(new EnvelopedManifest()
                                .withSignedDataObject(new DataObjectReference("xades4j:3"))
                        )
                )
                .withResourceResolver(new ResourceResolverSpi()
                {
                    @Override
                    public XMLSignatureInput engineResolveURI(ResourceResolverContext context)
                    {
                        return new XMLSignatureStreamInput(new ByteArrayInputStream(context.uriToResolve.getBytes()));
                    }

                    @Override
                    public boolean engineCanResolveURI(ResourceResolverContext context)
                    {
                        return context.uriToResolve.startsWith("xades4j:");
                    }
                });

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        AllwaysNullAlgsParamsMarshaller algsParamsMarshaller = new AllwaysNullAlgsParamsMarshaller();

        SignedDataObjectsProcessor processor = new SignedDataObjectsProcessor(new SignatureAlgorithms(), algsParamsMarshaller);
        SignedDataObjectsProcessor.Result result = processor.process(signedObjects, xmlSignature);

        // Simulate what's done during signature production
        doc.appendChild(xmlSignature.getElement());
        for (Manifest m : result.manifests)
        {
            m.generateDigestValues();
        }

        assertEquals(1, result.referenceMappings.size());
        assertEquals(2, result.manifests.size());
        assertEquals(2, xmlSignature.getObjectLength());
        assertEquals(1, xmlSignature.getSignedInfo().getLength());

        Manifest manifest1 = new Manifest(DOMHelper.getFirstChildElement(xmlSignature.getObjectItem(1).getElement()), "");
        assertEquals("sigId-manifest0", manifest1.getId());
        assertEquals(3, manifest1.getLength());

        Reference ref11 = manifest1.item(0);
        assertEquals("xades4j:1", ref11.getURI());
        assertEquals("sigId-manifest0-ref0", ref11.getId());
        assertNotEquals(0, ref11.getDigestValue().length);

        Reference ref12 = manifest1.item(1);
        assertEquals("xades4j:2", ref12.getURI());
        assertEquals("sigId-manifest0-ref1", ref12.getId());
        assertNotEquals(0, ref12.getDigestValue().length);

        Reference ref13 = manifest1.item(2);
        assertEquals("#sigId-manifest0-manifest2", ref13.getURI());
        assertEquals("sigId-manifest0-ref2", ref13.getId());
        assertNotEquals(0, ref13.getDigestValue().length);

        Manifest manifest2 = new Manifest(DOMHelper.getFirstChildElement(xmlSignature.getObjectItem(0).getElement()), "");
        assertEquals(1, manifest2.getLength());
        assertEquals("sigId-manifest0-manifest2", manifest2.getId());

        Reference ref21 = manifest2.item(0);
        assertEquals("xades4j:3", ref21.getURI());
        assertEquals("sigId-manifest0-manifest2-ref0", ref21.getId());
        assertNotEquals(0, ref21.getDigestValue().length);
    }

    @Test
    void testAddNullReference() throws Exception
    {
        Document doc = SignatureServicesTestBase.getNewDocument();

        SignedDataObjects dataObjsDescs = new SignedDataObjects()
                .withSignedDataObject(new AnonymousDataObjectReference("data".getBytes()));

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        SignedDataObjectsProcessor processor = new SignedDataObjectsProcessor(new SignatureAlgorithms(), new AllwaysNullAlgsParamsMarshaller());
        SignedDataObjectsProcessor.Result result = processor.process(dataObjsDescs, xmlSignature);

        assertEquals(1, result.referenceMappings.size());
        assertEquals(0, xmlSignature.getObjectLength());
        assertEquals(1, xmlSignature.getSignedInfo().getLength());

        Reference r = xmlSignature.getSignedInfo().item(0);
        assertNull(r.getElement().getAttributeNodeNS(Constants.SignatureSpecNS, "URI"));
    }

    @Test
    void testAddMultipleNullReferencesFails() throws Exception
    {
        SignedDataObjects dataObjsDescs = new SignedDataObjects();
        assertThrows(IllegalStateException.class, () -> {
            dataObjsDescs
                    .withSignedDataObject(new AnonymousDataObjectReference("data1".getBytes()))
                    .withSignedDataObject(new AnonymousDataObjectReference("data2".getBytes()));
        });
    }
}
