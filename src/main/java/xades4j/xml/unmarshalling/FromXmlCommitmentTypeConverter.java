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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import xades4j.properties.CommitmentTypePropertyBase;
import xades4j.xml.bind.xades.XmlCommitmentTypeIndicationType;
import xades4j.xml.bind.xades.XmlSignedDataObjectPropertiesType;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.xml.bind.xades.XmlAnyType;
import xades4j.xml.bind.xades.XmlCommitmentTypeQualifiersListType;

/**
 *
 * @author Luís
 */
class FromXmlCommitmentTypeConverter implements SignedDataObjPropFromXmlConv
{
    @Override
    public void convertFromObjectTree(
            XmlSignedDataObjectPropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        List<XmlCommitmentTypeIndicationType> xmlCommitments = xmlProps.getCommitmentTypeIndication();
        if (xmlCommitments.isEmpty())
        {
            return;
        }

        for (XmlCommitmentTypeIndicationType xmlCommitment : xmlCommitments)
        {
            List<String> objsRefs = xmlCommitment.getObjectReference();
            Object allDataObjs = xmlCommitment.getAllSignedDataObjects();

            if (objsRefs.isEmpty())
            {
                // Should be AllSignedDataObjects.
                objsRefs = null;
                if (null == allDataObjs)
                {
                    throw new PropertyUnmarshalException("ObjectReference or AllSignedDataObjects have to be present", CommitmentTypePropertyBase.PROP_NAME);
                }
            } else if (allDataObjs != null)
            {
                throw new PropertyUnmarshalException("Both ObjectReference and AllSignedDataObjects are present", CommitmentTypePropertyBase.PROP_NAME);
            }

            CommitmentTypeData commTypeData = new CommitmentTypeData(
                    xmlCommitment.getCommitmentTypeId().getIdentifier().getValue(),
                    xmlCommitment.getCommitmentTypeId().getDescription());
            commTypeData.setObjReferences(objsRefs);

            XmlCommitmentTypeQualifiersListType xmlQualifiers = xmlCommitment.getCommitmentTypeQualifiers();
            if (xmlQualifiers != null)
            {
                Collection qualifiers = new ArrayList();
                for (XmlAnyType xmlQualifier : xmlQualifiers.getCommitmentTypeQualifier())
                {
                    if (!xmlQualifier.getContent().isEmpty())
                    {
                        if (xmlQualifier.getContent().size() > 1)
                        {
                            throw new PropertyUnmarshalException("Qualifiers with multiple children are not support", CommitmentTypePropertyBase.PROP_NAME);
                        }

                        qualifiers.add(xmlQualifier.getContent().get(0));
                    }
                }
                
                commTypeData.setQualifiers(qualifiers);
            }

            propertyDataCollector.addCommitmentType(commTypeData);
        }
    }
}
