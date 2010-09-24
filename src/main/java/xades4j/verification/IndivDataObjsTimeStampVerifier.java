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

import com.google.inject.Inject;
import java.util.Date;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.verification.QualifyingPropertyVerificationContext.SignedObjectsData;

/**
 * XAdES section G.2.2.16.1.2
 * @author Luís
 */
class IndivDataObjsTimeStampVerifier implements QualifyingPropertyVerifier<IndividualDataObjsTimeStampData>
{
    private final TimeStampVerificationProvider timeStampVerifier;

    @Inject
    public IndivDataObjsTimeStampVerifier(
            TimeStampVerificationProvider timeStampVerifier)
    {
        this.timeStampVerifier = timeStampVerifier;
    }

    @Override
    public QualifyingProperty verify(
            IndividualDataObjsTimeStampData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        SignedObjectsData dataObjsData = ctx.getSignedObjectsData();

        IndividualDataObjsTimeStampProperty prop = new IndividualDataObjsTimeStampProperty();

        TimeStampDigestInput digestInput = new TimeStampDigestInput(propData.getCanonicalizationAlgorithmUri());
        try
        {
            for (String objRef : propData.getIncludes())
            {
                RawDataObjectDesc o = dataObjsData.findSignedDataObject(objRef);
                if (null == o)
                    throw new TimeStampDigestInputException(IndividualDataObjsTimeStampProperty.PROP_NAME);

                digestInput.addReference(o.getReference());
                // No problem because when an exception is thrown the data
                // structures in the verification process are not reused.
                o.withDataObjectTimeStamp(prop);
            }
        } catch (CannotAddDataToDigestInputException ex)
        {
            throw new TimeStampDigestInputException(IndividualDataObjsTimeStampProperty.PROP_NAME);
        }

        Date time = TimeStampUtils.verifyTokens(propData, digestInput, timeStampVerifier, IndividualDataObjsTimeStampProperty.PROP_NAME);
        prop.setTime(time);
        return prop;
    }
}
