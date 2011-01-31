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
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;
import xades4j.utils.DOMHelper;

/**
 *
 * @author Luís
 */
class DataGenSigTimeStamp implements PropertyDataObjectGenerator<SignatureTimeStampProperty>
{
    private final TimeStampTokenProvider timeStampTokenProvider;

    @Inject
    public DataGenSigTimeStamp(TimeStampTokenProvider timeStampTokenProvider)
    {
        this.timeStampTokenProvider = timeStampTokenProvider;
    }

    @Override
    public PropertyDataObject generatePropertyData(
            SignatureTimeStampProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        Element sigValueElem = DOMHelper.getFirstDescendant(
                ctx.getTargetXmlSignature().getElement(),
                Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);
        String canonAlgUri = ctx.getAlgorithmsProvider().getCanonicalizationAlgorithmForTimeStampProperties();
        TimeStampDigestInput tsDigestInput = new TimeStampDigestInput(canonAlgUri);
        try
        {
            tsDigestInput.addNode(sigValueElem);
        } catch (CannotAddDataToDigestInputException ex)
        {
            throw new PropertyDataGenerationException("Cannot create signature timestamp input: " + ex.getMessage(), prop);
        }

        try
        {
            TimeStampTokenRes tsTknRes = timeStampTokenProvider.getTimeStampToken(
                    tsDigestInput.getBytes(),
                    ctx.getAlgorithmsProvider().getDigestAlgorithmForTimeStampProperties());
            prop.setTime(tsTknRes.timeStampTime);
            return new SignatureTimeStampData(canonAlgUri, tsTknRes.encodedTimeStampToken);
        } catch (TimeStampTokenGenerationException ex)
        {
            throw new PropertyDataGenerationException("cannot get a time-stamp: " + ex.getMessage(), prop);
        }
    }
}
