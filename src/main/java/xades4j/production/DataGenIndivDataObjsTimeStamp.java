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

import xades4j.algorithms.Algorithm;
import xades4j.properties.DataObjectDesc;
import com.google.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.apache.xml.security.signature.Reference;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;
import xades4j.utils.TimeStampDigestInputFactory;

/**
 *
 * @author Luís
 */
class DataGenIndivDataObjsTimeStamp extends DataGenBaseTimeStamp<IndividualDataObjsTimeStampProperty>
{
    @Inject
    public DataGenIndivDataObjsTimeStamp(
            TimeStampTokenProvider timeStampTokenProvider,
            AlgorithmsProviderEx algorithmsProvider,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(algorithmsProvider, timeStampTokenProvider,timeStampDigestInputFactory);
    }

    @Override
    protected void addPropSpecificTimeStampInput(
            IndividualDataObjsTimeStampProperty prop,
            TimeStampDigestInput digestInput,
            PropertiesDataGenerationContext ctx) throws CannotAddDataToDigestInputException
    {
        Collection<DataObjectDesc> targetDataObjs = prop.getTargetDataObjects();
        Map<DataObjectDesc, Reference> refsMaps = ctx.getReferencesMappings();

        for (DataObjectDesc dataObj : targetDataObjs)
        {
            Reference r = refsMaps.get(dataObj);
            digestInput.addReference(r);
        }
    }

    @Override
    protected BaseXAdESTimeStampData createPropDataObj(
            IndividualDataObjsTimeStampProperty prop,
            Algorithm c14n,
            TimeStampTokenRes tsTknRes,
            PropertiesDataGenerationContext ctx)
    {
        Collection<DataObjectDesc> targetDataObjs = prop.getTargetDataObjects();
        Map<DataObjectDesc, Reference> refsMaps = ctx.getReferencesMappings();

        List<String> includes = new ArrayList<String>(targetDataObjs.size());
        for (DataObjectDesc dataObj : targetDataObjs)
        {
            Reference r = refsMaps.get(dataObj);
            includes.add('#' + r.getId());
        }

        prop.setTime(tsTknRes.timeStampTime);
        return new IndividualDataObjsTimeStampData(c14n, includes, tsTknRes.encodedTimeStampToken);
    }
}
