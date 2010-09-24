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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
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
public class DataObjectDescsProcessorTest
{
    public DataObjectDescsProcessorTest()
    {
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Before
    public void setUp()
    {
    }

    @After
    public void tearDown()
    {
    }

    @Test
    public void testProcess() throws Exception
    {
        System.out.println("process");

        Init.initXMLSec();
        Document doc = SignatureServicesTestBase.getNewDocument();

        Collection<DataObjectDesc> dataObjsDescs = new ArrayList<DataObjectDesc>(3);
        dataObjsDescs.add(new DataObjectReference("uri"));
        dataObjsDescs.add(new EnvelopedXmlObject(doc.createElement("test1")));
        dataObjsDescs.add(new EnvelopedXmlObject(doc.createElement("test2"), "text/xml", null));
        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");

        Map<DataObjectDesc, Reference> result = DataObjectDescsProcessor.process(
                dataObjsDescs, xmlSignature, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        assertEquals(result.size(), dataObjsDescs.size());
        assertEquals(xmlSignature.getObjectLength(), 2);
        assertEquals(xmlSignature.getSignedInfo().getLength(), dataObjsDescs.size());

        ObjectContainer obj = xmlSignature.getObjectItem(1);
        assertEquals(obj.getMimeType(), "text/xml");
        assertTrue(StringUtils.isNullOrEmptyString(obj.getEncoding()));

    }
}
