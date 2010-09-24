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

import xades4j.properties.DataObjectFormatProperty;
import xades4j.utils.ObjectUtils;

/**
 *
 * @author Luís
 */
class DataObjectFormatDataStructureVerifier implements PropertyDataObjectStructureVerifier
{
    @Override
    public void verifyStructure(PropertyDataObject propData) throws PropertyDataStructureException
    {
        DataObjectFormatData dataObjFormatData = (DataObjectFormatData)propData;

        // XAdES 7.2.5: "The mandatory ObjectReference attribute (...)."
        if (null == dataObjFormatData.getObjectRef())
            throw new PropertyDataStructureException("object reference not set", DataObjectFormatProperty.PROP_NAME);

        // XAdES 7.2.5: "At least one element of Description, ObjectIdentifier
        // and MimeType MUST be present within the property."
        if (ObjectUtils.allNull(
                dataObjFormatData.getMimeType(),
                dataObjFormatData.getIdentifier(),
                dataObjFormatData.getDescription()))
            throw new PropertyDataStructureException("At least one of description, object identifier and mime-type must be present", DataObjectFormatProperty.PROP_NAME);
    }
}
