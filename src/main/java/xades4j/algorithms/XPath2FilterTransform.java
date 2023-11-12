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
 *
 * @author Luís
 */
public final class XPath2FilterTransform extends XPathTransformBase
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

        /**
         * Creates a new {@code XPath2FilterTransform} with a single intersect
         * filter.
         * @param xpath the filter expression
         * @return the transform
         */
        public static XPath2FilterTransform intersect(String xpath)
        {
            return new XPath2FilterTransform().intersect(xpath);
        }

        /**
         * Creates a new {@code XPath2FilterTransform} with a single subtract
         * filter.
         * @param xpath the filter expression
         * @return the transform
         */
        public static XPath2FilterTransform subtract(String xpath)
        {
            return new XPath2FilterTransform().subtract(xpath);
        }

        /**
         * Creates a new {@code XPath2FilterTransform} with a single union
         * filter.
         * @param xpath the filter expression
         * @return the transform
         */
        public static XPath2FilterTransform union(String xpath)
        {
            return new XPath2FilterTransform().union(xpath);
        }
    }
    private final List<XPath2Filter> filters;

    private XPath2FilterTransform()
    {
        super(Transforms.TRANSFORM_XPATH2FILTER);
        this.filters = new ArrayList<>(2);
    }

    /**
     * Adds a new intersect filter to the current transform.
     * @param xpath the filter expression
     * @return the current transform
     */
    public XPath2FilterTransform intersect(String xpath)
    {
        this.filters.add(new XPath2Filter(XPath2FilterContainer.INTERSECT, xpath));
        return this;
    }

    /**
     * Adds a new subtract filter to the current transform.
     * @param xpath the filter expression
     * @return the current transform
     */
    public XPath2FilterTransform subtract(String xpath)
    {
        this.filters.add(new XPath2Filter(XPath2FilterContainer.SUBTRACT, xpath));
        return this;
    }

    /**
     * Adds a new union filter to the current transform.
     * @param xpath the filter expression
     * @return the current transform
     */
    public XPath2FilterTransform union(String xpath)
    {
        this.filters.add(new XPath2Filter(XPath2FilterContainer.UNION, xpath));
        return this;
    }

    /**
     * Gets the filters of the current transform.
     * @return an immutable list of filters
     */
    public List<XPath2Filter> getFilters()
    {
        return Collections.unmodifiableList(this.filters);
    }
    
    /**
     * Registers a namespace and the corresponding prefix to be used when resolving
     * the XPath filter expressions of the current transform.
     * For simplicity, the namespace declaration will be added to <b>all</b> the
     * resulting {@code XPath} parameter elements.
     * 
     * @param prefix the namespace prefix
     * @param namespace the namespace URI
     * 
     * @return the current instance
     */
    public XPath2FilterTransform withNamespace(String prefix, String namespace)
    {
        addNamespace(prefix, namespace);
        return this;
    }
}
