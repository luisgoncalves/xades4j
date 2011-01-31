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
package xades4j.xml.marshalling;

import xades4j.properties.data.PropertyDataObject;

/**
 * Thrown during the marshalling stage if a proeprty data object is not supported
 * by the {@code PropertiesMarshaller}s in use.
 * @author Luís
 */
public class UnsupportedDataObjectException extends MarshalException
{
    private final PropertyDataObject dataObject;

    public UnsupportedDataObjectException(PropertyDataObject dataObject)
    {
        this.dataObject = dataObject;
    }

    public PropertyDataObject getDataObject()
    {
        return dataObject;
    }

    @Override
    public String getMessage()
    {
        return "Unsupported property data object: " + dataObject.getClass().getName();
    }
}
