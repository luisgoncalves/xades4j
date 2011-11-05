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

import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.HelperNodeList;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import xades4j.production.XPath2FilterTransform;
import xades4j.production.XPath2FilterTransform.XPathFilter;

/**
 *
 * @author Luís
 */
public final class XPath2FilterTransformParamsMarshaller implements DataObjectTransformParamsMarshaller<XPath2FilterTransform>
{
    @Override
    public NodeList marshalParameters(XPath2FilterTransform t, Document doc)
    {
        HelperNodeList nl = new HelperNodeList();

        for (XPathFilter filter : t.getFilters())
        {
            XPath2FilterContainer c = null;
            switch (filter.getFilterType())
            {
                case INTERSECT:
                    c = XPath2FilterContainer.newInstanceIntersect(doc, filter.getXPath());
                    break;
                case SUBTRACT:
                    c = XPath2FilterContainer.newInstanceSubtract(doc, filter.getXPath());
                    break;
                case UNION:
                    c = XPath2FilterContainer.newInstanceUnion(doc, filter.getXPath());
                    break;
            }
            nl.appendChild(c.getElement());
        }

        return nl;
    }
}