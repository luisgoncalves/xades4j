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

import xades4j.properties.data.TimeStampValidationDataData;
import xades4j.xml.bind.xades.XmlAnyType;
import xades4j.xml.bind.xades.XmlCRLValuesType;
import xades4j.xml.bind.xades.XmlCertificateValuesType;
import xades4j.xml.bind.xades.XmlEncapsulatedPKIDataType;
import xades4j.xml.bind.xades.XmlRevocationValuesType;
import xades4j.xml.bind.xades.XmlUnsignedSignaturePropertiesType;
import xades4j.xml.bind.xades.XmlValidationDataType;

public class FromXmlTimeStampValidationDataConverter implements
        UnsignedSigPropFromXmlConv
{

    @Override
    public void convertFromObjectTree(
            XmlUnsignedSignaturePropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector)
            throws PropertyUnmarshalException
    {
        List<XmlValidationDataType> xmlTimeStampValidationData =
                xmlProps.getTimeStampValidationData();
        convertFromObject(xmlTimeStampValidationData, propertyDataCollector);
    }

    public void convertFromObject(
            List<XmlValidationDataType> xmlTimeStampValidationData,
            QualifyingPropertiesDataCollector propertyDataCollector)
                    throws PropertyUnmarshalException
    {
        if (null == xmlTimeStampValidationData || xmlTimeStampValidationData.isEmpty())
            return;

        TimeStampValidationDataData timeStampValidationDataData =
                new TimeStampValidationDataData();

        for (XmlValidationDataType xmlVDT : xmlTimeStampValidationData)
        {
            if (xmlVDT.getCertificateValues() != null)
            {
                XmlCertificateValuesType xmlCertificateValues = xmlVDT.getCertificateValues();

                List<Object> certValues = xmlCertificateValues.getEncapsulatedX509CertificateOrOtherCertificate();
                for (Object item : certValues)
                {
                    if (item instanceof XmlEncapsulatedPKIDataType)
                    {
                        XmlEncapsulatedPKIDataType cert = (XmlEncapsulatedPKIDataType) item;
                        timeStampValidationDataData.addCertificateData(cert.getValue());
                    }
                    if (item instanceof XmlAnyType)
                        throw new PropertyUnmarshalException("Property not supprted", "OtherCertificate");
                }
            }

            XmlRevocationValuesType xmlRevocationValues = xmlVDT.getRevocationValues();
            if (xmlRevocationValues != null && xmlRevocationValues.getCRLValues() != null)
            {
                XmlCRLValuesType crlValues = xmlRevocationValues.getCRLValues();
                List<XmlEncapsulatedPKIDataType> crls = crlValues.getEncapsulatedCRLValue();
                for (XmlEncapsulatedPKIDataType crl : crls)
                {
                    timeStampValidationDataData.addCRLData(crl.getValue());
                }

                // check for unsupported data
                if (xmlRevocationValues.getOCSPValues() != null)
                    throw new PropertyUnmarshalException("OCSP responses are unsupported",
                            "TimeStampValidationData");
                if (xmlRevocationValues.getOtherValues() != null)
                    throw new PropertyUnmarshalException("Other (not CRL and not OCSP) " +
                                "certificate revocation values unsupported",
                                "TimeStampValidationData");
            }
        }

        propertyDataCollector.addTimeStampValidationDataData(timeStampValidationDataData);
    }
}
