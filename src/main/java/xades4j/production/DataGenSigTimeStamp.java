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
import com.google.inject.Inject;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;
import xades4j.utils.DOMHelper;
import xades4j.utils.TimeStampDigestInputFactory;

/**
 *
 * @author Luís
 */
class DataGenSigTimeStamp extends DataGenBaseTimeStamp<SignatureTimeStampProperty>
{
    @Inject
    public DataGenSigTimeStamp(
            TimeStampTokenProvider timeStampTokenProvider,
            AlgorithmsProviderEx algorithmsProvider,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(algorithmsProvider, timeStampTokenProvider, timeStampDigestInputFactory);
    }

    @Override
    protected void addPropSpecificTimeStampInput(
            SignatureTimeStampProperty prop,
            TimeStampDigestInput digestInput,
            PropertiesDataGenerationContext ctx) throws CannotAddDataToDigestInputException
    {
        Element sigValueElem = DOMHelper.getFirstDescendant(
            ctx.getTargetXmlSignature().getElement(),
            Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);

        digestInput.addNode(sigValueElem);
    }

    @Override
    protected BaseXAdESTimeStampData createPropDataObj(
            SignatureTimeStampProperty prop,
            Algorithm c14n,
            TimeStampTokenRes tsTknRes,
            PropertiesDataGenerationContext ctx)
    {
        prop.setTime(tsTknRes.timeStampTime);
        return new SignatureTimeStampData(c14n, tsTknRes.encodedTimeStampToken);
    }
}
