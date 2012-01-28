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

import xades4j.algorithms.XPath2FilterTransform;
import java.util.List;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class XPath2FilterTransformTest
{
    @Test
    public void testCreation()
    {
        XPath2FilterTransform t1 = XPath2Filter.intersect("1");
        XPath2FilterTransform t2 = t1.union("2");
        XPath2FilterTransform t3 = t2.subtract("3");

        assertNotSame(t1, t2);
        assertNotSame(t2, t3);

        List<XPath2Filter> filters = t3.getFilters();
        assertEquals(3, filters.size());

        XPath2Filter f = filters.get(0);
        assertEquals("1", f.getXPath());
        assertEquals("intersect", f.getFilterType());

        f = filters.get(1);
        assertEquals("2", f.getXPath());
        assertEquals("union", f.getFilterType());

        f = filters.get(2);
        assertEquals("3", f.getXPath());
        assertEquals("subtract", f.getFilterType());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testChangeFiltersListFails()
    {
        XPath2FilterTransform t = XPath2Filter.intersect("1").union("2");
        t.getFilters().clear();
    }
}
