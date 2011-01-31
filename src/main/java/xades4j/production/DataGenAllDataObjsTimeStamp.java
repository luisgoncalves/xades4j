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
package xades4j.production;

import com.google.inject.Inject;
import java.util.List;
import org.apache.xml.security.signature.Reference;
import xades4j.properties.AllDataObjsTimeStampProperty;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.AllDataObjsTimeStampData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;

/**
 *
 * @author Luís
 */
class DataGenAllDataObjsTimeStamp implements PropertyDataObjectGenerator<AllDataObjsTimeStampProperty>
{
    private final TimeStampTokenProvider timeStampTokenProvider;

    @Inject
    public DataGenAllDataObjsTimeStamp(
            TimeStampTokenProvider timeStampTokenProvider)
    {
        this.timeStampTokenProvider = timeStampTokenProvider;
    }

    @Override
    public PropertyDataObject generatePropertyData(
            AllDataObjsTimeStampProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        List<Reference> refs = ctx.getReferences();
        String canonAlgUri = ctx.getAlgorithmsProvider().getCanonicalizationAlgorithmForTimeStampProperties();
        TimeStampDigestInput digestInput = new TimeStampDigestInput(canonAlgUri);

        try
        {
            for (Reference r : refs)
            {
                digestInput.addReference(r);
            }
            TimeStampTokenRes tsTknRes = timeStampTokenProvider.getTimeStampToken(
                    digestInput.getBytes(),
                    ctx.getAlgorithmsProvider().getDigestAlgorithmForTimeStampProperties());
            prop.setTime(tsTknRes.timeStampTime);
            return new AllDataObjsTimeStampData(canonAlgUri, tsTknRes.encodedTimeStampToken);
        } catch (CannotAddDataToDigestInputException ex)
        {
            throw new PropertyDataGenerationException("Cannot create all data objects time stamp input: " + ex.getMessage(), prop);
        } catch (TimeStampTokenGenerationException ex)
        {
            throw new PropertyDataGenerationException("Cannot get a time-stamp: " + ex.getMessage(), prop);
        }


    }
}
