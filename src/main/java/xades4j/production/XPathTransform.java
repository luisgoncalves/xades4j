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
import org.apache.xml.security.transforms.params.XPathContainer;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import xades4j.utils.DOMHelper;

/**
 * The XPath filtering transform.
 * @author Luís
 */
public final class XPathTransform extends Algorithm
{
    private final String xpath;

    /**
     * Creates a new instance of the transform
     * @param xpath the XPath filtering expression
     */
    public XPathTransform(String xpath)
    {
        super(Transforms.TRANSFORM_XPATH);
        if (null == xpath)
        {
            throw new NullPointerException("XPath expression cannot be null");
        }
        this.xpath = xpath;
    }

    @Override
    public NodeList getParams(Document signatureDocument)
    {
        XPathContainer xpathContainer = new XPathContainer(signatureDocument);
        xpathContainer.setXPath(this.xpath);
        return DOMHelper.nodeList(xpathContainer.getElement());
    }
}
