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
package xades4j.algorithms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;

/**
 * The XPath 2.0 transform. Instances of the transform can be initially created
 * using the static methods of {@link XPath2Filter}: {@link XPath2Filter#intersect(java.lang.String) intersect},
 * {@link XPath2Filter#subtract(java.lang.String) subtract}, and
 * {@link XPath2Filter#union(java.lang.String) union}. The transform can them  be
 * composed as follows:
 * <p>
 * <code>
 * XPath2FilterTransform t = XPath2Filter.subtract("xpath1").intersect("xpath2");
 * </code>
 * <p>
 * Instances of this class are immutable.
 *
 * @author Luís
 */
public final class XPath2FilterTransform extends Algorithm
{
    /**
     * A filter for the XPath 2.0 transform. The static methods on this class can
     * be used to create new instances of the transform.
     */
    public static final class XPath2Filter
    {
        private final String filterType;
        private final String xpath;

        private XPath2Filter(String filterType, String xpath)
        {
            if (null == xpath)
            {
                throw new NullPointerException("XPath expression cannot be null");
            }

            this.filterType = filterType;
            this.xpath = xpath;
        }

        /**
         * Gets the type of this filter ({@code "intersect"}, {@code "subtract"} or {@code "union"}).
         * @return the filter's type
         */
        public String getFilterType()
        {
            return filterType;
        }

        /**
         * Gets the filtering expression.
         * @return the filter's xpath expression
         */
        public String getXPath()
        {
            return xpath;
        }
        /**/
        /**********************************************************************/
        /**/
        private static final XPath2FilterTransform emptyTransform;

        static
        {
            List<XPath2Filter> emptyFilters = Collections.emptyList();
            emptyTransform = new XPath2FilterTransform(emptyFilters);
        }

        /**
         * Creates a new {@code XPath2FilterTransform} with a single intersect
         * filter.
         * @param xpath the filter expression
         * @return the transform
         */
        public static XPath2FilterTransform intersect(String xpath)
        {
            return emptyTransform.intersect(xpath);
        }

        /**
         * Creates a new {@code XPath2FilterTransform} with a single subtract
         * filter.
         * @param xpath the filter expression
         * @return the transform
         */
        public static XPath2FilterTransform subtract(String xpath)
        {
            return emptyTransform.subtract(xpath);
        }

        /**
         * Creates a new {@code XPath2FilterTransform} with a single union
         * filter.
         * @param xpath the filter expression
         * @return the transform
         */
        public static XPath2FilterTransform union(String xpath)
        {
            return emptyTransform.union(xpath);
        }
    }
    private final List<XPath2Filter> filters;

    private XPath2FilterTransform(List<XPath2Filter> filters)
    {
        super(Transforms.TRANSFORM_XPATH2FILTER);
        this.filters = Collections.unmodifiableList(filters);
    }

    /**
     * Creates a new {@code XPath2FilterTransform} that contains the filters on
     * the current instance plus a new intersect filter.
     * @param xpath the filter expression
     * @return the new transform
     */
    public XPath2FilterTransform intersect(String xpath)
    {
        return cloneAndAddNewFilter(XPath2FilterContainer.INTERSECT, xpath);
    }

    /**
     * Creates a new {@code XPath2FilterTransform} that contains the filters on
     * the current instance plus a new subtract filter.
     * @param xpath the filter expression
     * @return the new transform
     */
    public XPath2FilterTransform subtract(String xpath)
    {
        return cloneAndAddNewFilter(XPath2FilterContainer.SUBTRACT, xpath);
    }

    /**
     * Creates a new {@code XPath2FilterTransform} that contains the filters on
     * the current instance plus a new union filter.
     * @param xpath the filter expression
     * @return the new transform
     */
    public XPath2FilterTransform union(String xpath)
    {
        return cloneAndAddNewFilter(XPath2FilterContainer.UNION, xpath);
    }

    private XPath2FilterTransform cloneAndAddNewFilter(String filterType, String xpath)
    {
        List<XPath2Filter> newFilters = new ArrayList<XPath2Filter>(this.filters);
        newFilters.add(new XPath2Filter(filterType, xpath));
        return new XPath2FilterTransform(newFilters);
    }

    /**
     * Gets the filters of the current transform.
     * @return the immutable list of filters
     */
    public List<XPath2Filter> getFilters()
    {
        return this.filters;
    }
}
