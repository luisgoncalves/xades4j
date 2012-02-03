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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.data.ArchiveTimeStampData;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.utils.DOMHelper;
import xades4j.utils.TimeStampDigestInput;
import xades4j.utils.TimeStampDigestInputFactory;

/**
 *
 * @author Luís
 */
class DataGenArchiveTimeStamp extends DataGenBaseTimeStamp<ArchiveTimeStampProperty>
{
    @Inject
    public DataGenArchiveTimeStamp(
            AlgorithmsProviderEx algorithmsProvider,
            TimeStampTokenProvider timeStampTokenProvider,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(algorithmsProvider, timeStampTokenProvider, timeStampDigestInputFactory);
    }

    @Override
    protected void addPropSpecificTimeStampInput(
            ArchiveTimeStampProperty prop,
            TimeStampDigestInput digestInput,
            PropertiesDataGenerationContext ctx) throws CannotAddDataToDigestInputException, PropertyDataGenerationException
    {
        Element unsignedSigPropsElem = DOMHelper.getFirstDescendant(
                ctx.getTargetXmlSignature().getElement(),
                QualifyingProperty.XADES_XMLNS, QualifyingProperty.UNSIGNED_SIGNATURE_PROPS_TAG);
        if (null == unsignedSigPropsElem)
            throw new PropertyDataGenerationException(prop, "no unsigned signature properties to get inputs");

        try
        {
            // References, processed accordingly to XML-DSIG.
            List<Reference> refs = ctx.getReferences();
            for (Reference r : refs)
            {
                digestInput.addReference(r);
            }

            // SignedInfo.
            Element e = ctx.getTargetXmlSignature().getSignedInfo().getElement();
            digestInput.addNode(e);

            // SignatureValue.
            e = DOMHelper.getFirstDescendant(
                    ctx.getTargetXmlSignature().getElement(),
                    Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);
            digestInput.addNode(e);

            // KeyInfo, if present.
            KeyInfo ki = ctx.getTargetXmlSignature().getKeyInfo();
            if (ki != null)
                digestInput.addNode(ki.getElement());

            // Unsigned properties, in order of appearence.
            Map<String, Integer> propsCnt = new HashMap<String, Integer>(5);
            propsCnt.put(CertificateValuesProperty.PROP_NAME, 0);
            propsCnt.put(RevocationValuesProperty.PROP_NAME, 0);
            propsCnt.put(CompleteCertificateRefsProperty.PROP_NAME, 0);
            propsCnt.put(CompleteRevocationRefsProperty.PROP_NAME, 0);
            propsCnt.put(SignatureTimeStampProperty.PROP_NAME, 0);

            e = DOMHelper.getFirstChildElement(unsignedSigPropsElem);
            // UnsignedProperties shouldn't be empty!
            do
            {
                digestInput.addNode(e);

                Integer pCnt = propsCnt.get(e.getLocalName());
                if (pCnt != null)
                    propsCnt.put(e.getLocalName(), pCnt += 1);

            } while ((e = DOMHelper.getNextSiblingElement(e)) != null);

            for (Map.Entry<String, Integer> entry : propsCnt.entrySet())
            {
                if (entry.getValue() == 0)
                    throw new PropertyDataGenerationException(prop, String.format("no %s for input", entry.getKey()));
            }

            // Objects, except the one containing the qualifying properties.
            for (int i = 0; i < ctx.getTargetXmlSignature().getObjectLength(); i++)
            {
                ObjectContainer obj = ctx.getTargetXmlSignature().getObjectItem(i);
                if (null == DOMHelper.getFirstDescendant(obj.getElement(), QualifyingProperty.XADES_XMLNS, "*"))
                    digestInput.addNode(obj.getElement());
            }

        } catch (CannotAddDataToDigestInputException ex)
        {
            throw new PropertyDataGenerationException(prop, "cannot create time stamp input", ex);
        }
    }

    @Override
    protected BaseXAdESTimeStampData createPropDataObj(
            ArchiveTimeStampProperty prop,
            Algorithm c14n,
            TimeStampTokenRes tsTknRes,
            PropertiesDataGenerationContext ctx)
    {
        prop.setTime(tsTknRes.timeStampTime);
        return new ArchiveTimeStampData(c14n, tsTknRes.encodedTimeStampToken);
    }
}
