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

package xades4j.production;

import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.junit.Test;
import static org.junit.Assert.*;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import xades4j.utils.SignatureServicesTestBase;

/**
 *
 * @author Luís
 */
public class XPath2FilterTransformTest
{
    @Test
    public void testGetParams() throws Exception
    {
        System.out.println("getParams");

        XPath2FilterTransform instance = new XPath2FilterTransform()
                .intersect("intersect-xpath")
                .union("union-xpath")
                .subtract("subtract-xpath");

        NodeList result = instance.getParams(SignatureServicesTestBase.getNewDocument());
        assertFilterAreEqual(result.item(0), XPath2FilterContainer.INTERSECT, "intersect-xpath");
        assertFilterAreEqual(result.item(1), XPath2FilterContainer.UNION, "union-xpath");
        assertFilterAreEqual(result.item(2), XPath2FilterContainer.SUBTRACT, "subtract-xpath");
    }

    private static void assertFilterAreEqual(
            Node filterNode,
            String filterType,
            String filterXpath)
    {
        String filterNodeFilterType = filterNode.getAttributes().getNamedItem("Filter").getNodeValue();
        String filterNodeFilterXpath = filterNode.getTextContent();

        assertEquals(filterType, filterNodeFilterType);
        assertEquals(filterXpath, filterNodeFilterXpath);
    }
}
