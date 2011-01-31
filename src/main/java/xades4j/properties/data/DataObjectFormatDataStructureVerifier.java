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
