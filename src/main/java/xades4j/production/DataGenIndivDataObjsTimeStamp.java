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
package xades4j.production;

import xades4j.properties.DataObjectDesc;
import com.google.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.apache.xml.security.signature.Reference;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;

/**
 *
 * @author Luís
 */
class DataGenIndivDataObjsTimeStamp implements PropertyDataObjectGenerator<IndividualDataObjsTimeStampProperty>
{
    private final TimeStampTokenProvider timeStampTokenProvider;

    @Inject
    public DataGenIndivDataObjsTimeStamp(
            TimeStampTokenProvider timeStampTokenProvider)
    {
        this.timeStampTokenProvider = timeStampTokenProvider;
    }

    @Override
    public PropertyDataObject generatePropertyData(
            IndividualDataObjsTimeStampProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        Collection<DataObjectDesc> targetDataObjs = prop.getTargetDataObjects();
        Map<DataObjectDesc, Reference> refsMaps = ctx.getReferencesMappings();
        String canonAlgUri = ctx.getAlgorithmsProvider().getCanonicalizationAlgorithmForTimeStampProperties();
        TimeStampDigestInput digestInput = new TimeStampDigestInput(canonAlgUri);
        List<String> includes = new ArrayList<String>(targetDataObjs.size());

        try
        {
            for (DataObjectDesc dataObj : targetDataObjs)
            {
                Reference r = refsMaps.get(dataObj);
                digestInput.addReference(r);
                includes.add('#' + r.getId());
            }
        } catch (CannotAddDataToDigestInputException ex)
        {
            throw new PropertyDataGenerationException("Cannot create individual data objects time stamp input: " + ex.getMessage(), prop);
        }

        try
        {
            TimeStampTokenRes tsTknRes = timeStampTokenProvider.getTimeStampToken(
                    digestInput.getBytes(),
                    ctx.getAlgorithmsProvider().getDigestAlgorithmForTimeStampProperties());
            prop.setTime(tsTknRes.timeStampTime);
            return new IndividualDataObjsTimeStampData(canonAlgUri, includes, tsTknRes.encodedTimeStampToken);
        } catch (TimeStampTokenGenerationException ex)
        {
            throw new PropertyDataGenerationException("Cannot get a time-stamp: " + ex.getMessage(), prop);
        }
    }
}
