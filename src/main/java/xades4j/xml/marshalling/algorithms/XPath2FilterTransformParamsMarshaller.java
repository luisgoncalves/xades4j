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
package xades4j.xml.marshalling.algorithms;

import java.util.ArrayList;
import java.util.List;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.algorithms.XPath2FilterTransform;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;

/**
 *
 * @author Luís
 */
final class XPath2FilterTransformParamsMarshaller implements AlgorithmParametersMarshaller<XPath2FilterTransform>
{
    @Override
    public List<Node> marshalParameters(XPath2FilterTransform alg, Document doc)
    {
        List<XPath2Filter> filters = alg.getFilters();
        List<Node> params = new ArrayList<Node>(filters.size());

        for (XPath2Filter filter : filters)
        {
            XPath2FilterContainer c = null;
            String filterType = filter.getFilterType();
            if (XPath2FilterContainer.INTERSECT.equals(filterType))
            {
                c = XPath2FilterContainer.newInstanceIntersect(doc, filter.getXPath());
            }
            else if (XPath2FilterContainer.SUBTRACT.equals(filterType))
            {
                c = XPath2FilterContainer.newInstanceSubtract(doc, filter.getXPath());
            }
            else if (XPath2FilterContainer.UNION.equals(filterType))
            {
                c = XPath2FilterContainer.newInstanceUnion(doc, filter.getXPath());
            }
            else
            {
                throw new IllegalArgumentException(filterType);
            }
            params.add(c.getElement());
        }
        return params;
    }
}
