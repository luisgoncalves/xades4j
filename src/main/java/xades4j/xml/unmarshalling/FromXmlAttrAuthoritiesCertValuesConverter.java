/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS
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

import xades4j.properties.data.AttrAuthoritiesCertValuesData;
import xades4j.xml.bind.xades.XmlAnyType;
import xades4j.xml.bind.xades.XmlCertificateValuesType;
import xades4j.xml.bind.xades.XmlEncapsulatedPKIDataType;
import xades4j.xml.bind.xades.XmlUnsignedSignaturePropertiesType;

public class FromXmlAttrAuthoritiesCertValuesConverter implements
        UnsignedSigPropFromXmlConv
{

    @Override
    public void convertFromObjectTree(
            XmlUnsignedSignaturePropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector)
            throws PropertyUnmarshalException
    {
        XmlCertificateValuesType xmlCertificateValues = xmlProps.getAttrAuthoritiesCertValues();
        if (null == xmlCertificateValues)
            return;

        AttrAuthoritiesCertValuesData attrAuthoritiesCertValuesData =
                new AttrAuthoritiesCertValuesData();
        List<Object> values = xmlCertificateValues.getEncapsulatedX509CertificateOrOtherCertificate();
        for (Object item : values)
        {
            if (item instanceof XmlEncapsulatedPKIDataType)
            {
                XmlEncapsulatedPKIDataType cert = (XmlEncapsulatedPKIDataType) item;
                attrAuthoritiesCertValuesData.addData(cert.getValue());
            }
            if (item instanceof XmlAnyType)
                throw new PropertyUnmarshalException("Property not supported", "OtherCertificate");
        }

        propertyDataCollector.setAttrAuthoritiesCertValues(attrAuthoritiesCertValuesData);
    }
}
