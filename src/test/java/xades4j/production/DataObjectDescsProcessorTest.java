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

import xades4j.algorithms.EnvelopedSignatureTransform;
import org.apache.xml.security.utils.Constants;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import xades4j.properties.DataObjectDesc;
import xades4j.utils.SignatureServicesTestBase;
import xades4j.utils.StringUtils;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class DataObjectDescsProcessorTest extends SignatureServicesTestBase
{

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        Init.initXMLSec();
    }

    @Test
    public void testProcess() throws Exception
    {
        System.out.println("process");

        Document doc = getNewDocument();

        SignedDataObjects dataObjsDescs = new SignedDataObjects()
            .withSignedDataObject(new DataObjectReference("uri").withTransform(new EnvelopedSignatureTransform()))
            .withSignedDataObject(new EnvelopedXmlObject(doc.createElement("test1")))
            .withSignedDataObject(new EnvelopedXmlObject(doc.createElement("test2"), "text/xml", null));

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        AllwaysNullAlgsParamsMarshaller algsParamsMarshaller = new AllwaysNullAlgsParamsMarshaller();

        DataObjectDescsProcessor processor = new DataObjectDescsProcessor(new TestAlgorithmsProvider(), algsParamsMarshaller);
        Map<DataObjectDesc, Reference> result = processor.process(dataObjsDescs, xmlSignature);

        assertEquals(dataObjsDescs.getDataObjectsDescs().size(), result.size());
        assertEquals(2, xmlSignature.getObjectLength());
        assertEquals(xmlSignature.getSignedInfo().getLength(), dataObjsDescs.getDataObjectsDescs().size());

        assertEquals(1, algsParamsMarshaller.getInvokeCount());
        Reference ref = xmlSignature.getSignedInfo().item(0);
        assertEquals(1, ref.getTransforms().getLength());

        ObjectContainer obj = xmlSignature.getObjectItem(1);
        assertEquals("text/xml", obj.getMimeType());
        assertTrue(StringUtils.isNullOrEmptyString(obj.getEncoding()));

    }

    @Test
    public void testAddNullReference() throws Exception
    {
        System.out.println("addNullReference");

        Document doc = SignatureServicesTestBase.getNewDocument();

        SignedDataObjects dataObjsDescs = new SignedDataObjects()
            .withSignedDataObject(new AnonymousDataObjectReference("data".getBytes()));

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        DataObjectDescsProcessor processor = new DataObjectDescsProcessor(new TestAlgorithmsProvider(), new AllwaysNullAlgsParamsMarshaller());
        Map<DataObjectDesc, Reference> result = processor.process(dataObjsDescs, xmlSignature);

        assertEquals(1, result.size());
        assertEquals(0, xmlSignature.getObjectLength());
        assertEquals(1, xmlSignature.getSignedInfo().getLength());

        Reference r = xmlSignature.getSignedInfo().item(0);
        assertNull(r.getElement().getAttributeNodeNS(Constants.SignatureSpecNS, "URI"));
    }

    @Test(expected = IllegalStateException.class)
    public void testAddMultipleNullReferencesFails() throws Exception
    {
        System.out.println("addMultipleNullReferencesFails");

        Document doc = SignatureServicesTestBase.getNewDocument();

        SignedDataObjects dataObjsDescs = new SignedDataObjects()
            .withSignedDataObject(new AnonymousDataObjectReference("data1".getBytes()))
            .withSignedDataObject(new AnonymousDataObjectReference("data2".getBytes()));

        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        DataObjectDescsProcessor processor = new DataObjectDescsProcessor(new TestAlgorithmsProvider(), new AllwaysNullAlgsParamsMarshaller());
        Map<DataObjectDesc, Reference> result = processor.process(dataObjsDescs, xmlSignature);
    }
}
