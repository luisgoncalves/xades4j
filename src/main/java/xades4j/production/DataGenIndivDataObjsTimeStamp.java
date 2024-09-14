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

import jakarta.inject.Inject;
import org.apache.xml.security.signature.Reference;
import xades4j.algorithms.Algorithm;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.utils.TimeStampDigestInput;
import xades4j.utils.TimeStampDigestInputFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 *
 * @author Luís
 */
class DataGenIndivDataObjsTimeStamp extends DataGenBaseTimeStamp<IndividualDataObjsTimeStampProperty>
{
    @Inject
    public DataGenIndivDataObjsTimeStamp(
            TimeStampTokenProvider timeStampTokenProvider,
            SignatureAlgorithms signatureAlgorithms,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(signatureAlgorithms, timeStampTokenProvider,timeStampDigestInputFactory);
    }

    @Override
    protected void addPropSpecificTimeStampInput(
            IndividualDataObjsTimeStampProperty prop,
            TimeStampDigestInput digestInput,
            PropertiesDataGenerationContext ctx) throws CannotAddDataToDigestInputException
    {
        for (DataObjectDesc dataObj : prop.getTargetDataObjects())
        {
            Reference r = ctx.getReference(dataObj);
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

        List<String> includes = new ArrayList<>(targetDataObjs.size());
        for (DataObjectDesc dataObj : targetDataObjs)
        {
            Reference r = ctx.getReference(dataObj);
            includes.add('#' + ctx.ensureElementId(r));
        }

        prop.setTime(tsTknRes.timeStampTime);
        return new IndividualDataObjsTimeStampData(c14n, includes, tsTknRes.encodedTimeStampToken);
    }
}
