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

import org.junit.Test;
import static org.junit.Assert.*;
import xades4j.production.XPath2FilterTransform.XPathFilter;

/**
 *
 * @author Luís
 */
public class XPath2FilterTransformTest
{
    @Test
    public void testGetFilters()
    {
        System.out.println("getFilters");

        XPath2FilterTransform instance = new XPath2FilterTransform(
                XPathFilter.intersect("intersect-xpath"),
                XPathFilter.union("union-xpath"),
                XPathFilter.subtract("subtract-xpath"));

        XPathFilter[] result = instance.getFilters();
        assertFilterAreEqual(result[0], XPathFilter.FilterType.INTERSECT, "intersect-xpath");
        assertFilterAreEqual(result[1], XPathFilter.FilterType.UNION, "union-xpath");
        assertFilterAreEqual(result[2], XPathFilter.FilterType.SUBTRACT, "subtract-xpath");
    }

    private static void assertFilterAreEqual(
            XPathFilter filter,
            XPathFilter.FilterType filterType, String xpath)
    {
        assertEquals(filterType, filter.getFilterType());
        assertEquals(xpath, filter.getXPath());
    }
}
