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

import java.util.ArrayList;
import java.util.List;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.HelperNodeList;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 * The XPath 2.0 transform.
 *
 * @see DataObjectTransform
 * @author Luís
 */
public final class XPath2FilterTransform extends DataObjectTransform
{
    private interface XPath2FilterContainerCreator
    {
        XPath2FilterContainer create(String xpath, Document doc);
    }

    private static final XPath2FilterContainerCreator intersectCreator = new XPath2FilterContainerCreator()
    {
        @Override
        public XPath2FilterContainer create(String xpath, Document doc)
        {
            return XPath2FilterContainer.newInstanceIntersect(doc, xpath);
        }
    };
    private static final XPath2FilterContainerCreator subtractCreator = new XPath2FilterContainerCreator()
    {
        @Override
        public XPath2FilterContainer create(String xpath, Document doc)
        {
            return XPath2FilterContainer.newInstanceSubtract(doc, xpath);
        }
    };
    private static final XPath2FilterContainerCreator unionCreator = new XPath2FilterContainerCreator()
    {
        @Override
        public XPath2FilterContainer create(String xpath, Document doc)
        {
            return XPath2FilterContainer.newInstanceUnion(doc, xpath);
        }
    };

    /**************************************************************************/

    private final List<XPath2FilterContainerCreator> creators;
    private final List<String> xpaths;

    /**
     * At least <b>one filter</b> has to be specified after creating the transform instance
     * using {@link #intersect(java.lang.String) intersect}, {@link #subtract(java.lang.String) subtract}
     * or {@link #union(java.lang.String) union} methods.
     *
     */
    public XPath2FilterTransform()
    {
        super(Transforms.TRANSFORM_XPATH2FILTER);
        this.creators = new ArrayList<XPath2FilterContainerCreator>(3);
        this.xpaths = new ArrayList<String>(3);
    }

    private void addXPath(String xpath)
    {
        if(null == xpath)
        {
            throw new NullPointerException("XPath expression cannot be null");
        }
        this.xpaths.add(xpath);
    }

    public XPath2FilterTransform intersect(String xpath)
    {
        addXPath(xpath);
        this.creators.add(intersectCreator);
        return this;
    }

    public XPath2FilterTransform subtract(String xpath)
    {
        addXPath(xpath);
        this.creators.add(subtractCreator);
        return this;
    }

    public XPath2FilterTransform union(String xpath)
    {
        addXPath(xpath);
        this.creators.add(unionCreator);
        return this;
    }

    @Override
    protected NodeList getParams(Document signatureDocument)
    {
        if(this.xpaths.isEmpty())
        {
            throw new NullPointerException("No filters were specified for XPath2FilterTransform");
        }

        HelperNodeList params = new HelperNodeList();

        for (int i = 0; i < this.xpaths.size(); i++)
        {
            XPath2FilterContainerCreator c = this.creators.get(i);
            params.appendChild(
                    c.create(this.xpaths.get(i), signatureDocument).getElement());
        }
        
        return params;
    }
}
