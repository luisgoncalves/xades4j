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

import org.apache.xml.security.utils.HelperNodeList;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Represents a generic data object transform with optional parameters
 *
 * @author Luís
 */
public class GenericDataObjectTransform extends DataObjectTransform
{
    private final NodeList transformParams;

    public GenericDataObjectTransform(String transformUri)
    {
        this(transformUri, (NodeList) null);
    }

    public GenericDataObjectTransform(String transformUri, NodeList transformParams)
    {
        super(transformUri);
        this.transformParams = transformParams;
    }

    public GenericDataObjectTransform(String transformUri, Node transformParams)
    {
        super(transformUri);
        HelperNodeList nl = new HelperNodeList();
        nl.appendChild(transformParams);
        this.transformParams = nl;
    }

    public NodeList getTransformParams()
    {
        return transformParams;
    }
}
