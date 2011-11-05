/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

package xades4j.xml.marshalling.transforms;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import xades4j.production.XPath2FilterTransform;
import xades4j.production.XPath2FilterTransform.XPathFilter;
import xades4j.utils.SignatureServicesTestBase;

/**
 *
 * @author Luís
 */
public class XPath2FilterTransformParamsMarshallerTest {

    public XPath2FilterTransformParamsMarshallerTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Test
    public void testMarshalParameters() throws Exception
    {
        System.out.println("marshalParameters");

        String[] expressions = new String[]{ "intersect-xpath", "union-xpath", "subtract-xpath" };
        String[] filters = new String[]{ "intersect", "union", "subtract" };
        XPath2FilterTransform t = new XPath2FilterTransform(
            XPathFilter.intersect(expressions[0]),
            XPathFilter.union(expressions[1]),
            XPathFilter.subtract(expressions[2]));
        
        Document doc = SignatureServicesTestBase.getNewDocument();
        XPath2FilterTransformParamsMarshaller instance = new XPath2FilterTransformParamsMarshaller();
        
        NodeList params = instance.marshalParameters(t, doc);

        assertEquals(expressions.length, params.getLength());
        for (int i = 0; i < params.getLength(); i++)
        {
            Node p = params.item(i);
            assertEquals(Node.ELEMENT_NODE, p.getNodeType());
            assertEquals("XPath", p.getNodeName());
            Node filter = p.getAttributes().getNamedItem("Filter");
            assertNotNull(filter);
            assertEquals(filters[i], filter.getNodeValue());
        }
    }
}