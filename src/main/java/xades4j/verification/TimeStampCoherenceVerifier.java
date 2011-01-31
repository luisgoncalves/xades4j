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
import xades4j.properties.AllDataObjsTimeStampProperty;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.utils.DataGetter;

/**
 *
 * @author Luís
 */
class TimeStampCoherenceVerifier implements CustomSignatureVerifier
{
    @Override
    public void verify(
            XAdESVerificationResult verificationData,
            QualifyingPropertyVerificationContext ctx) throws TimeStampCoherenceException
    {
        DataGetter<QualifyingProperty> propsGetter = verificationData.getPropertiesFilter();
        Collection<SignatureTimeStampProperty> sigTimeStamps = propsGetter.getOfType(SignatureTimeStampProperty.class);
        Collection<AllDataObjsTimeStampProperty> allDataObjsTimeStamps = propsGetter.getOfType(AllDataObjsTimeStampProperty.class);
        Collection<IndividualDataObjsTimeStampProperty> indivDataObjsTimeStamps = propsGetter.getOfType(IndividualDataObjsTimeStampProperty.class);

        // XAdES G.2.2.16.1.3 Checking SignatureTimeStamp:
        // "Check for coherence in the values of the times indicated in the time-stamp
        // tokens. They have to be posterior to the times indicated in the time-stamp
        // tokens contained within AllDataObjectsTimeStamp or IndividualDataObjectsTimeStamp,
        // if present."
        //
        // I use Date.before() because the time-stamps may be equal (same second).

        for (SignatureTimeStampProperty sigTs : sigTimeStamps)
        {

            for (IndividualDataObjsTimeStampProperty indivDObjTs : indivDataObjsTimeStamps)
            {
                if (sigTs.getTime().before(indivDObjTs.getTime()))
                    throw new TimeStampCoherenceException(SignatureTimeStampProperty.PROP_NAME, "time-stamp not posterior to data objects time-stamps");
            }

            for (AllDataObjsTimeStampProperty allDObjTs : allDataObjsTimeStamps)
            {
                if (sigTs.getTime().before(allDObjTs.getTime()))
                    throw new TimeStampCoherenceException(SignatureTimeStampProperty.PROP_NAME, "time-stamp not posterior to data objects time-stamps");
            }
        }

    }
}
