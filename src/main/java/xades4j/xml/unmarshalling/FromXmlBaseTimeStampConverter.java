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
package xades4j.xml.unmarshalling;

import java.util.List;
import org.apache.xml.security.c14n.Canonicalizer;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.xml.bind.xades.XmlEncapsulatedPKIDataType;
import xades4j.xml.bind.xades.XmlXAdESTimeStampType;
import xades4j.xml.bind.xmldsig.XmlCanonicalizationMethodType;

/**
 *
 * @author Luís
 */
abstract class FromXmlBaseTimeStampConverter
{
    protected void convertTimeStamps(
            List<XmlXAdESTimeStampType> xmlTimeStamps,
            QualifyingPropertiesDataCollector propertyDataCollector,
            String propName) throws PropertyUnmarshalException
    {
        if (null == xmlTimeStamps || xmlTimeStamps.isEmpty())
            return;

        for (XmlXAdESTimeStampType xmlTS : xmlTimeStamps)
        {
            if(!xmlTS.getReferenceInfo().isEmpty())
                throw new PropertyUnmarshalException("ReferenceInfo is not supported in XAdESTimeStamp", propName);

            XmlCanonicalizationMethodType xmlCanonMethod = xmlTS.getCanonicalizationMethod();
            BaseXAdESTimeStampData tsData = createTSData(
                    null == xmlCanonMethod ? Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS : xmlCanonMethod.getAlgorithm());

            List<Object> tsTokens = xmlTS.getEncapsulatedTimeStampOrXMLTimeStamp();
            if (tsTokens.isEmpty())
                throw new PropertyUnmarshalException("No time-stamp tokens", propName);

            for (Object tkn : tsTokens)
            {
                if (!(tkn instanceof XmlEncapsulatedPKIDataType))
                    throw new PropertyUnmarshalException("XML time-stamps are not supported", propName);
                tsData.addTimeStampToken(((XmlEncapsulatedPKIDataType)tkn).getValue());
            }

            doSpecificConvert(xmlTS, tsData);

            setTSData(tsData, propertyDataCollector);
        }
    }

    protected abstract BaseXAdESTimeStampData createTSData(String canonAlgUri);

    /**
     * Override if needed.
     */
    protected void doSpecificConvert(
            XmlXAdESTimeStampType xmlTS,
            BaseXAdESTimeStampData tsData) throws PropertyUnmarshalException
    {
        if(!xmlTS.getInclude().isEmpty())
            throw new PropertyUnmarshalException("Includes should not be present", "");
    }

    protected abstract void setTSData(
            BaseXAdESTimeStampData tsData,
            QualifyingPropertiesDataCollector propertyDataCollector);
}
