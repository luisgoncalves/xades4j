/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
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

import xades4j.properties.data.RevocationValuesData;
import xades4j.xml.bind.xades.XmlCRLValuesType;
import xades4j.xml.bind.xades.XmlEncapsulatedPKIDataType;
import xades4j.xml.bind.xades.XmlRevocationValuesType;
import xades4j.xml.bind.xades.XmlUnsignedSignaturePropertiesType;

public class FromXmlRevocationValuesConverter implements UnsignedSigPropFromXmlConv
{
    @Override
    public void convertFromObjectTree(
            XmlUnsignedSignaturePropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector)
            throws PropertyUnmarshalException
    {
        XmlRevocationValuesType xmlRevocationValues = xmlProps.getRevocationValues();
        convertFromObject(xmlRevocationValues, propertyDataCollector);
    }

    public void convertFromObject(XmlRevocationValuesType xmlRevocationValues,
            QualifyingPropertiesDataCollector propertyDataCollector)
                    throws PropertyUnmarshalException
    {
        if (null == xmlRevocationValues)
            return;

        RevocationValuesData revocationValuesData = new RevocationValuesData();
        XmlCRLValuesType values = xmlRevocationValues.getCRLValues();
        List<XmlEncapsulatedPKIDataType> crls = values.getEncapsulatedCRLValue();
        for (XmlEncapsulatedPKIDataType crl : crls)
        {
            revocationValuesData.addData(crl.getValue());
        }

        // handle unsupported data
        if (xmlRevocationValues.getOCSPValues() != null)
            throw new PropertyUnmarshalException("OCSP responses are unsupported",
                    "RevocationValues");
        if (xmlRevocationValues.getOtherValues() != null)
            throw new PropertyUnmarshalException("Other (not CRL and not OCSP) " +
                    "certificate revocation values unsupported", "RevocationValues");

        propertyDataCollector.setRevocationValues(revocationValuesData);
    }
}
