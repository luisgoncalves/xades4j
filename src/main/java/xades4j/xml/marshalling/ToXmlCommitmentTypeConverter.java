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

import java.util.Collection;
import org.w3c.dom.Document;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.xml.bind.xades.XmlAnyType;
import xades4j.xml.bind.xades.XmlCommitmentTypeIndicationType;
import xades4j.xml.bind.xades.XmlCommitmentTypeQualifiersListType;
import xades4j.xml.bind.xades.XmlIdentifierType;
import xades4j.xml.bind.xades.XmlObjectIdentifierType;
import xades4j.xml.bind.xades.XmlSignedPropertiesType;

/**
 *
 * @author Luís
 */
class ToXmlCommitmentTypeConverter implements SignedPropertyDataToXmlConverter
{

    @Override
    public void convertIntoObjectTree(
            PropertyDataObject propData,
            XmlSignedPropertiesType xmlProps,
            Document doc)
    {
        CommitmentTypeData commitmentTypeData = (CommitmentTypeData) propData;

        // Create the JAXB CommitmentTypeIndication and add it to SignedDataObjectProperties.
        XmlCommitmentTypeIndicationType xmlCommitmentTypeProp = new XmlCommitmentTypeIndicationType();
        xmlProps.getSignedDataObjectProperties().getCommitmentTypeIndication().add(xmlCommitmentTypeProp);

        XmlIdentifierType xmlIdentifier = new XmlIdentifierType();
        xmlIdentifier.setValue(commitmentTypeData.getUri());
        XmlObjectIdentifierType xmlObjectId = new XmlObjectIdentifierType();
        xmlObjectId.setDescription(commitmentTypeData.getDescription());
        xmlObjectId.setIdentifier(xmlIdentifier);
        xmlCommitmentTypeProp.setCommitmentTypeId(xmlObjectId);

        Collection<String> refsUris = commitmentTypeData.getObjReferences();
        if (null == refsUris)
        {
            xmlCommitmentTypeProp.setAllSignedDataObjects();
        } else
        {
            xmlCommitmentTypeProp.getObjectReference().addAll(refsUris);
        }

        Collection qualifiers = commitmentTypeData.getQualifiers();
        if (!qualifiers.isEmpty())
        {
            XmlCommitmentTypeQualifiersListType xmlQualifiers = new XmlCommitmentTypeQualifiersListType();
            for (Object q : qualifiers)
            {
                XmlAnyType xmlQualifier = new XmlAnyType();
                xmlQualifier.getContent().add(q);
                
                xmlQualifiers.getCommitmentTypeQualifier().add(xmlQualifier);
            }
            
            xmlCommitmentTypeProp.setCommitmentTypeQualifiers(xmlQualifiers);
        }
    }
}
