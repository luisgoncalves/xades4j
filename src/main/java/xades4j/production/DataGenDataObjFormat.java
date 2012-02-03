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

import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.properties.data.PropertyDataObject;

/**
 *
 * @author Luís
 */
class DataGenDataObjFormat implements PropertyDataObjectGenerator<DataObjectFormatProperty>
{
    @Override
    public PropertyDataObject generatePropertyData(
            DataObjectFormatProperty prop,
            PropertiesDataGenerationContext ctx)
    {
        // DataObjectFormat applies to a single data object. The mandatory ObjectReference
        // attribute MUST reference the ds:Reference element of the ds:Signature
        // corresponding with the data object qualified by this property.
        // This assumes that the QualifyingProperties are in the signature's document.
        DataObjectDesc targetDataObjInfo = prop.getTargetDataObjects().iterator().next();
        String objRef = '#' + ctx.getReferencesMappings().get(targetDataObjInfo).getId();

        DataObjectFormatData dataObjFormatData = new DataObjectFormatData(objRef);
        dataObjFormatData.setMimeType(prop.getMimeType());
        dataObjFormatData.setEncoding(prop.getEncoding());
        dataObjFormatData.setDescription(prop.getDescription());
        dataObjFormatData.setIdentifier(prop.getIdentifier());
        dataObjFormatData.setDocumentationUris(prop.getDocumentationUris());

        return dataObjFormatData;
    }
}
