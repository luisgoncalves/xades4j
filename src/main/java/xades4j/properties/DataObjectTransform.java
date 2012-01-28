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
package xades4j.properties;

import org.w3c.dom.Element;
import xades4j.algorithms.Algorithm;

/**
 * @deprecated This class is deprecated and might be removed on future releases
 * @see xades4j.Algorithm
 *
 * @author Luís
 */
public class DataObjectTransform extends Algorithm
{
    private final Element transformParams;

    public DataObjectTransform(String transformUri, Element transformParams)
    {
        super(transformUri);
        this.transformParams = transformParams;
    }

    public DataObjectTransform(String transformUri)
    {
        this(transformUri, null);
    }

    public String getTransformUri()
    {
        return getUri();
    }

    public Element getTransformParams()
    {
        return transformParams;
    }
}
