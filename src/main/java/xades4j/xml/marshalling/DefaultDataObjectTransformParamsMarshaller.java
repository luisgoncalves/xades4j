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
package xades4j.xml.marshalling;

import java.util.HashMap;
import java.util.Map;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.HelperNodeList;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import xades4j.production.DataObjectTransform;
import xades4j.production.EnvelopedSignatureTransform;
import xades4j.production.GenericDataObjectTransform;
import xades4j.production.XPath2FilterTransform;
import xades4j.production.XPath2FilterTransform.XPathFilter;
import xades4j.production.XPathTransform;
import xades4j.utils.DOMHelper;

/**
 * The default marshaller of data object transforms.
 *
 * @see DataObjectTransform
 * @author Luís
 */
public class DefaultDataObjectTransformParamsMarshaller implements DataObjectTransformParamsMarshaller
{
    private final Map<Class<? extends DataObjectTransform>, DataObjectTransformParamsMarshaller> marshallers;

    public DefaultDataObjectTransformParamsMarshaller()
    {
        this.marshallers = new HashMap<Class<? extends DataObjectTransform>, DataObjectTransformParamsMarshaller>(4);
        this.marshallers.put(EnvelopedSignatureTransform.class, new NopDataObjectTransformParamsMarshaller());
        this.marshallers.put(XPathTransform.class, new XPathTransformParamsMarshaller());
        this.marshallers.put(XPath2FilterTransform.class, null);
        this.marshallers.put(GenericDataObjectTransform.class, new GenericDataObjectTransformParamsMarshaller());
    }

    @Override
    public NodeList marshalParameters(DataObjectTransform t, Document doc)
    {
        DataObjectTransformParamsMarshaller marshaller = this.marshallers.get(t.getClass());
        if (null == marshaller)
        {
            throw new UnsupportedOperationException("Unsupported property");
        }
        return marshaller.marshalParameters(t, doc);
    }
}

class NopDataObjectTransformParamsMarshaller implements DataObjectTransformParamsMarshaller
{
    @Override
    public NodeList marshalParameters(DataObjectTransform t, Document doc)
    {
        return null;
    }
}

class XPathTransformParamsMarshaller implements DataObjectTransformParamsMarshaller
{
    @Override
    public NodeList marshalParameters(DataObjectTransform t, Document doc)
    {
        XPathContainer xpathContainer = new XPathContainer(doc);
        xpathContainer.setXPath(((XPathTransform) t).getXPath());
        return DOMHelper.nodeList(xpathContainer.getElement());
    }
}

class XPath2FilterTransformParamsMarshaller implements DataObjectTransformParamsMarshaller
{
    @Override
    public NodeList marshalParameters(DataObjectTransform t, Document doc)
    {
        HelperNodeList nl = new HelperNodeList();
        XPath2FilterTransform transf = (XPath2FilterTransform) t;

        for (XPathFilter filter : transf.getFilters())
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

class GenericDataObjectTransformParamsMarshaller implements DataObjectTransformParamsMarshaller
{
    @Override
    public NodeList marshalParameters(DataObjectTransform t, Document doc)
    {
        return ((GenericDataObjectTransform) t).getTransformParams();
    }
}
