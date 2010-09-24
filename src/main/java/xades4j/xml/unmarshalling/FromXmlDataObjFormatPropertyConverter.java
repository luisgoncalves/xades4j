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
package xades4j.xml.unmarshalling;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import xades4j.properties.IdentifierType;
import xades4j.xml.bind.xades.XmlDataObjectFormatType;
import xades4j.xml.bind.xades.XmlDocumentationReferencesType;
import xades4j.xml.bind.xades.XmlQualifierType;
import xades4j.xml.bind.xades.XmlSignedDataObjectPropertiesType;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.xml.bind.xades.XmlObjectIdentifierType;

/**
 *
 * @author Luís
 */
class FromXmlDataObjFormatPropertyConverter implements SignedDataObjPropFromXmlConv
{
    @Override
    public void convertFromObjectTree(
            XmlSignedDataObjectPropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        List<XmlDataObjectFormatType> xmlFormats = xmlProps.getDataObjectFormat();
        if (xmlFormats.isEmpty())
            return;

        for (XmlDataObjectFormatType xmlDataObjFormat : xmlFormats)
        {
            XmlObjectIdentifierType xmlObjId = xmlDataObjFormat.getObjectIdentifier();

            DataObjectFormatData dataObjFormatData = new DataObjectFormatData(xmlDataObjFormat.getObjectReference());
            dataObjFormatData.setIdentifier(FromXmlUtils.getObjectIdentifier(xmlObjId));
            dataObjFormatData.setMimeType(xmlDataObjFormat.getMimeType());
            dataObjFormatData.setEncoding(xmlDataObjFormat.getEncoding());
            dataObjFormatData.setDescription(xmlDataObjFormat.getDescription());

            if (xmlObjId != null)
            {
                XmlDocumentationReferencesType docRefs = xmlDataObjFormat.getObjectIdentifier().getDocumentationReferences();
                if (docRefs != null && !docRefs.getDocumentationReference().isEmpty())
                    dataObjFormatData.setDocumentationUris(docRefs.getDocumentationReference());
            }

            propertyDataCollector.addDataObjectFormat(dataObjFormatData);
        }
    }
}
