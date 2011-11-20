/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
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

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import xades4j.utils.DOMHelper;

/**
 * Base class for transforms that are applied to a data object. Each {@code DataObjectTransform}
 * that is applied to a data object will result in a {@code ds:Transform} element
 * within the corresponding {@code ds:Reference} in the signature.
 *
 * @see DataObjectDesc#withTransform(xades4j.properties.DataObjectTransform)
 *
 * @author Luís
 */
public class DataObjectTransform
{
    private final String uri;
    private final NodeList params;

    public DataObjectTransform(String uri, NodeList params)
    {
        if (uri == null)
        {
            throw new NullPointerException("Transform URI cannot be null");
        }
        this.uri = uri;
        this.params = params;
    }

    public DataObjectTransform(String transformUri, Node... transformParams)
    {
        this(transformUri, DOMHelper.nodeList(transformParams));
    }

    String getTransformUri()
    {
        return this.uri;
    }

    /**
     * Gets the transforms parameters. The signature document is passed because
     * it may allow a simpler public API on subclasses.
     * @param signatureDocument the document that owns the signature that contains the current transform
     * @return a node list with the transform paramters or {@code null} if none
     */
    protected NodeList getParams(Document signatureDocument)
    {
        return this.params;
    }
}
