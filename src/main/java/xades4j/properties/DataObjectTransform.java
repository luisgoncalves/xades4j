/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.properties;

import org.w3c.dom.Element;

/**
 * Represents a transform that is applied to a data object. Each instance of this
 * class that is applied to a data object will result in a {@code ds:Transform}
 * element within the corresponding {@code ds:Reference} in the signature.
 *
 * @see DataObjectDesc#withTransform(xades4j.properties.DataObjectTransform)
 *
 * @author Luís
 */
public class DataObjectTransform
{
    private final String transformUri;
    private final Element transformParams;

    public DataObjectTransform(
            String transformUri,
            Element paramsElement)
    {
        this.transformUri = transformUri;
        this.transformParams = paramsElement;
    }

    public DataObjectTransform(String transformUri)
    {
        this(transformUri, null);
    }

    public String getTransformUri()
    {
        return transformUri;
    }

    public Element getTransformParams()
    {
        return transformParams;
    }
}
