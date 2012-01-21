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

import com.google.inject.Inject;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.utils.TimeStampDigestInputFactory;
import xades4j.verification.QualifyingPropertyVerificationContext.SignedObjectsData;

/**
 * XAdES section G.2.2.16.1.2
 * @author Luís
 */
class IndivDataObjsTimeStampVerifier extends TimeStampVerifierBase<IndividualDataObjsTimeStampData>
{
    @Inject
    public IndivDataObjsTimeStampVerifier(
            TimeStampVerificationProvider timeStampVerifier,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(timeStampVerifier, timeStampDigestInputFactory, IndividualDataObjsTimeStampProperty.PROP_NAME);
    }

    @Override
    protected QualifyingProperty addPropSpecificTimeStampInputAndCreateProperty(
            IndividualDataObjsTimeStampData propData,
            TimeStampDigestInput digestInput,
            QualifyingPropertyVerificationContext ctx) throws CannotAddDataToDigestInputException, TimeStampVerificationException
    {
        SignedObjectsData dataObjsData = ctx.getSignedObjectsData();
        IndividualDataObjsTimeStampProperty prop = new IndividualDataObjsTimeStampProperty();

        for (String objRef : propData.getIncludes())
        {
            RawDataObjectDesc o = dataObjsData.findSignedDataObject(objRef);
            if (null == o)
            {
                throw new TimeStampDigestInputException(IndividualDataObjsTimeStampProperty.PROP_NAME);
            }
            digestInput.addReference(o.getReference());
            // No problem because when an exception is thrown the data
            // structures in the verification process are not reused.
            o.withDataObjectTimeStamp(prop);
        }
        return prop;
    }
}
