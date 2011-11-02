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

import org.apache.xml.security.transforms.Transforms;

/**
 * The XPath 2.0 transform.
 *
 * @see DataObjectTransform
 * @author Luís
 */
public final class XPath2FilterTransform extends DataObjectTransform
{
    /**
     * A XPath filter for the XPath 2.0 transform.
     */
    public static class XPathFilter
    {
        public enum XPathFilterType
        {
            INTERSECT,
            SUBTRACT,
            UNION
        }

        private final XPathFilterType filterType;
        private final String xpath;

        private XPathFilter(XPathFilterType filterType, String xpath)
        {
            if(null == xpath)
            {
                throw new NullPointerException("XPath expression cannot be null");
            }

            this.filterType = filterType;
            this.xpath = xpath;
        }

        public XPathFilterType getFilterType()
        {
            return filterType;
        }

        public String getXPath()
        {
            return xpath;
        }

        /**
         * Creates a new XPath intersect filter.
         * @param xpath the filte expression
         * @return the filter
         */
        public static XPathFilter intersect(String xpath)
        {
            return new XPathFilter(XPathFilterType.INTERSECT, xpath);
        }

        /**
         * Creates a new XPath subtract filter.
         * @param xpath the filte expression
         * @return the filter
         */
        public static XPathFilter subtract(String xpath)
        {
            return new XPathFilter(XPathFilterType.SUBTRACT, xpath);
        }

        /**
         * Creates a new XPath union filter.
         * @param xpath the filte expression
         * @return the filter
         */
        public static XPathFilter union(String xpath)
        {
            return new XPathFilter(XPathFilterType.UNION, xpath);
        }
    }
    /**/
    private final XPathFilter[] filters;

    public XPath2FilterTransform(XPathFilter... filters)
    {
        super(Transforms.TRANSFORM_XPATH2FILTER);
        if (null == filters)
        {
            throw new NullPointerException("XPath filters cannot be null");
        }
        if (filters.length == 0)
        {
            throw new IllegalArgumentException("At least one XPath filter must be specified");
        }
        this.filters = filters;
    }

    public XPathFilter[] getFilters()
    {
        return filters;
    }
}
