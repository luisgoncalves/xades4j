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

import xades4j.Algorithm;
import java.util.ArrayList;
import java.util.List;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;

/**
 * The XPath 2.0 transform.
 *
 * @author Luís
 */
public final class XPath2FilterTransform extends Algorithm
{
    /**
     * A XPath filter for the XPath 2.0 transform.
     */
    public static class XPathFilter
    {

        private final String filterType;
        private final String xpath;

        private XPathFilter(String filterType, String xpath)
        {
            if (null == xpath)
            {
                throw new NullPointerException("XPath expression cannot be null");
            }

            this.filterType = filterType;
            this.xpath = xpath;
        }

        public String getFilterType()
        {
            return filterType;
        }

        public String getXPath()
        {
            return xpath;
        }
    }
    /**************************************************************************/
    /**/
    private final List<XPathFilter> filters;

    /**
     * At least <b>one filter</b> must be specified after creating the transform instance
     * using {@link #intersect(java.lang.String) intersect}, {@link #subtract(java.lang.String) subtract}
     * or {@link #union(java.lang.String) union} methods.
     *
     */
    public XPath2FilterTransform()
    {
        super(Transforms.TRANSFORM_XPATH2FILTER);
        this.filters = new ArrayList<XPathFilter>(3);
    }

    public XPath2FilterTransform intersect(String xpath)
    {
        this.filters.add(new XPathFilter(XPath2FilterContainer.INTERSECT, xpath));
        return this;
    }

    public XPath2FilterTransform subtract(String xpath)
    {
        this.filters.add(new XPathFilter(XPath2FilterContainer.SUBTRACT, xpath));
        return this;
    }

    public XPath2FilterTransform union(String xpath)
    {
        this.filters.add(new XPathFilter(XPath2FilterContainer.UNION, xpath));
        return this;
    }

    public List<XPathFilter> getFilters()
    {
        return filters;
    }
}
