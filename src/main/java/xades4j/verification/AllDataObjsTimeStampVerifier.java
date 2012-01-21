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
import java.util.Collection;
import xades4j.properties.AllDataObjsTimeStampProperty;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.QualifyingProperty;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.AllDataObjsTimeStampData;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.utils.TimeStampDigestInputFactory;

/**
 * XAdES section G.2.2.16.1.1
 * @author Luís
 */
class AllDataObjsTimeStampVerifier extends TimeStampVerifierBase<AllDataObjsTimeStampData>
{

    @Inject
    public AllDataObjsTimeStampVerifier(
            TimeStampVerificationProvider timeStampVerifier,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(timeStampVerifier, timeStampDigestInputFactory, AllDataObjsTimeStampProperty.PROP_NAME);
    }

    @Override
    protected QualifyingProperty addPropSpecificTimeStampInputAndCreateProperty(AllDataObjsTimeStampData propData, TimeStampDigestInput digestInput, QualifyingPropertyVerificationContext ctx) throws CannotAddDataToDigestInputException
    {
        Collection<RawDataObjectDesc> dataObjs = ctx.getSignedObjectsData().getAllDataObjects();

        for (RawDataObjectDesc o : dataObjs)
        {
            digestInput.addReference(o.getReference());
        }

        return new AllDataObjsTimeStampProperty();
    }
}
