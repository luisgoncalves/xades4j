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

import org.apache.xml.security.transforms.params.XPathContainer;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import xades4j.production.DataObjectTransform;
import xades4j.production.XPathTransform;
import xades4j.utils.DOMHelper;

/**
 *
 * @author Luís
 */
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
