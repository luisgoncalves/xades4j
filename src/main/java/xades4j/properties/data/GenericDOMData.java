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
package xades4j.properties.data;

import org.w3c.dom.Element;

/**
 * A generic DOM container. This can be used to hold the final property element,
 * instead of having a specific {@code PropertyDataObject}. Please note that if
 * this type of data object is returned from the unmarshaler, the appropriate
 * verifier has to be set on {@link xades4j.verification.XadesVerificationProfile}
 * @author Luís
 */
public final class GenericDOMData implements PropertyDataObject
{
    private final Element propertyElement;

    public GenericDOMData(Element propertyElement)
    {
        this.propertyElement = propertyElement;
    }

    public Element getPropertyElement()
    {
        return propertyElement;
    }
}
