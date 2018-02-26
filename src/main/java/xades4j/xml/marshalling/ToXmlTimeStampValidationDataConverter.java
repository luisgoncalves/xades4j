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
package xades4j.xml.marshalling;

import java.util.Collection;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.w3c.dom.Document;

import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.TimeStampValidationDataData;
import xades4j.xml.bind.xades.ObjectFactory;
import xades4j.xml.bind.xades.XmlCRLValuesType;
import xades4j.xml.bind.xades.XmlCertificateValuesType;
import xades4j.xml.bind.xades.XmlEncapsulatedPKIDataType;
import xades4j.xml.bind.xades.XmlRevocationValuesType;
import xades4j.xml.bind.xades.XmlUnsignedPropertiesType;
import xades4j.xml.bind.xades.XmlValidationDataType;

public class ToXmlTimeStampValidationDataConverter implements
        UnsignedPropertyDataToXmlConverter
{

    @Override
    public void convertIntoObjectTree(PropertyDataObject propData,
            XmlUnsignedPropertiesType xmlProps, Document doc)
    {
        Collection<byte[]> certValues = ((TimeStampValidationDataData) propData).getCertificateData();
        Collection<byte[]> crlValues = ((TimeStampValidationDataData) propData).getCRLData();

        ObjectFactory objectFactory = new ObjectFactory();

        XmlValidationDataType xmlValidationDataType = objectFactory.createXmlValidationDataType();
        if (certValues != null && ! certValues.isEmpty())
        {
            XmlCertificateValuesType xmlCertificateValues = new XmlCertificateValuesType();
            List<Object> certList =
                    xmlCertificateValues.getEncapsulatedX509CertificateOrOtherCertificate();
            for (byte[] cert : certValues)
            {
                XmlEncapsulatedPKIDataType xmlEncodedCert = new XmlEncapsulatedPKIDataType();
                xmlEncodedCert.setValue(cert);
                certList.add(xmlEncodedCert);
            }
            xmlValidationDataType.setCertificateValues(xmlCertificateValues);
        }

        if (crlValues != null && ! crlValues.isEmpty())
        {
            XmlRevocationValuesType xmlRevocationValuesType = new XmlRevocationValuesType();
            XmlCRLValuesType xmlCRLValuesType = new XmlCRLValuesType();
            List<XmlEncapsulatedPKIDataType> crlList = xmlCRLValuesType.getEncapsulatedCRLValue();
            for (byte[] crl : crlValues)
            {
                XmlEncapsulatedPKIDataType xmlEncodedCrl = new XmlEncapsulatedPKIDataType();
                xmlEncodedCrl.setValue(crl);
                crlList.add(xmlEncodedCrl);
            }
            xmlRevocationValuesType.setCRLValues(xmlCRLValuesType);
            xmlValidationDataType.setRevocationValues(xmlRevocationValuesType);
        }

        JAXBElement<XmlValidationDataType> xmlTimeStampValidationData =
                objectFactory.createTimeStampValidationDataV1_4_1(xmlValidationDataType);
        xmlProps.getUnsignedSignatureProperties().getAny().add(xmlTimeStampValidationData);
    }
}
