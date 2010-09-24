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
package xades4j.xml.marshalling;

import java.util.Collection;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.xml.bind.xades.XmlCommitmentTypeIndicationType;
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
            XmlSignedPropertiesType xmlProps)
    {
        CommitmentTypeData commitmentTypeData = (CommitmentTypeData)propData;

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
            xmlCommitmentTypeProp.setAllSignedDataObjects();
        else
            xmlCommitmentTypeProp.getObjectReference().addAll(refsUris);
    }
}
