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
import java.util.Collection;
import org.w3c.dom.Document;
import xades4j.properties.ObjectIdentifier;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.xml.bind.xades.XmlDataObjectFormatType;
import xades4j.xml.bind.xades.XmlDocumentationReferencesType;
import xades4j.xml.bind.xades.XmlObjectIdentifierType;
import xades4j.xml.bind.xades.XmlSignedPropertiesType;

/**
 *
 * @author Luís
 */
class ToXmlDataObjectFormatConverter implements SignedPropertyDataToXmlConverter
{
    @Override
    public void convertIntoObjectTree(
            PropertyDataObject propData,
            XmlSignedPropertiesType xmlProps,
            Document doc)
    {
        DataObjectFormatData dataObjFormatData = (DataObjectFormatData)propData;

        XmlDataObjectFormatType xmlDataObjFormatProp = new XmlDataObjectFormatType();
        xmlDataObjFormatProp.setObjectReference(dataObjFormatData.getObjectRef());
        xmlDataObjFormatProp.setDescription(dataObjFormatData.getDescription());
        xmlDataObjFormatProp.setMimeType(dataObjFormatData.getMimeType());
        xmlDataObjFormatProp.setEncoding(dataObjFormatData.getEncoding());
        xmlDataObjFormatProp.setObjectIdentifier(getXmlObjId(dataObjFormatData));

        xmlProps.getSignedDataObjectProperties().getDataObjectFormat().add(xmlDataObjFormatProp);
    }

    private XmlObjectIdentifierType getXmlObjId(
            DataObjectFormatData dataObjFormatData)
    {
        ObjectIdentifier identifier = dataObjFormatData.getIdentifier();
        if (null == identifier)
            return null;

        XmlObjectIdentifierType xmlObjId = ToXmlUtils.getXmlObjectId(identifier);

        // Documentation references
        Collection<String> docsUris = dataObjFormatData.getDocumentationUris();
        if (docsUris != null && !docsUris.isEmpty())
        {
            XmlDocumentationReferencesType docRefs = new XmlDocumentationReferencesType();
            docRefs.getDocumentationReference().addAll(docsUris);
            xmlObjId.setDocumentationReferences(docRefs);
        }

        return xmlObjId;
    }
}
