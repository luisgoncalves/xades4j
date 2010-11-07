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
package xades4j.verification;

import java.util.Collection;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.CommitmentTypeProperty;
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
            return commitmentTypeProperty;
        }
        return new AllDataObjsCommitmentTypeProperty(uri, desc);
    }
}
