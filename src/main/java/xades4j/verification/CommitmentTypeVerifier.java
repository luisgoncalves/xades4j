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
package xades4j.verification;

import java.util.Collection;
import org.w3c.dom.Element;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.CommitmentTypePropertyBase;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.verification.QualifyingPropertyVerificationContext.SignedObjectsData;

/**
 * XAdES section G.2.2.9
 * @author Luís
 */
class CommitmentTypeVerifier implements QualifyingPropertyVerifier<CommitmentTypeData>
{
    @Override
    public QualifyingProperty verify(
            CommitmentTypeData propData,
            QualifyingPropertyVerificationContext ctx) throws CommitmentTypeVerificationException
    {
        String uri = propData.getUri(), desc = propData.getDescription();
        Collection<String> objsReferences = propData.getObjReferences();

        CommitmentTypePropertyBase property;
        
        if (objsReferences != null)
        {
            // "Check that all the ObjectReference elements actually reference
            // ds:Reference elements from the signature."

            SignedObjectsData signedObjsData = ctx.getSignedObjectsData();
            CommitmentTypeProperty commitmentTypeProperty = new CommitmentTypeProperty(uri, desc);

            for (String objRef : objsReferences)
            {
                RawDataObjectDesc dataObj = signedObjsData.findSignedDataObject(objRef);
                if (null == dataObj)
                    throw new CommitmentTypeVerificationException(objRef);

                // Associate the property to the data object.
                dataObj.withCommitmentType(commitmentTypeProperty);
            }
            property = commitmentTypeProperty;
        }
        else
        {
            property = new AllDataObjsCommitmentTypeProperty(uri, desc);
        }
        
        if (propData.getQualifiers() != null)
        {
            for (Object q : propData.getQualifiers())
            {
                if (q instanceof String)
                {
                    property.withQualifier((String)q);
                }
                else if (q instanceof Element)
                {
                    property.withQualifier((Element)q);
                }
            }
        }
        
        return property;
    }

    @Override
    public QualifyingProperty verify(CommitmentTypeData propData, Element elem,
            QualifyingPropertyVerificationContext ctx)
            throws InvalidPropertyException
    {
        return verify(propData, ctx);
    }
}
