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
