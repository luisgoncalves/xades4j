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
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
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
