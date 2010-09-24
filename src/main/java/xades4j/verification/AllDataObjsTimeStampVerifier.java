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
import java.util.Collection;
import java.util.Date;
import xades4j.properties.AllDataObjsTimeStampProperty;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.QualifyingProperty;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.AllDataObjsTimeStampData;
import xades4j.providers.TimeStampVerificationProvider;

/**
 * XAdES section G.2.2.16.1.1
 * @author Luís
 */
class AllDataObjsTimeStampVerifier implements QualifyingPropertyVerifier<AllDataObjsTimeStampData>
{
    private final TimeStampVerificationProvider timeStampVerifier;

    @Inject
    public AllDataObjsTimeStampVerifier(
            TimeStampVerificationProvider timeStampVerifier)
    {
        this.timeStampVerifier = timeStampVerifier;
    }

    @Override
    public QualifyingProperty verify(
            AllDataObjsTimeStampData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        Collection<RawDataObjectDesc> dataObjs = ctx.getSignedObjectsData().getAllDataObjects();

        TimeStampDigestInput digestInput = new TimeStampDigestInput(propData.getCanonicalizationAlgorithmUri());
        try
        {
            for (RawDataObjectDesc o : dataObjs)
            {
                digestInput.addReference(o.getReference());
            }
        } catch (CannotAddDataToDigestInputException ex)
        {
            throw new TimeStampDigestInputException(AllDataObjsTimeStampProperty.PROP_NAME);
        }

        Date time = TimeStampUtils.verifyTokens(propData, digestInput, timeStampVerifier, AllDataObjsTimeStampProperty.PROP_NAME);
        AllDataObjsTimeStampProperty ats = new AllDataObjsTimeStampProperty();
        ats.setTime(time);
        return ats;
    }
}
