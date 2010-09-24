/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.xml.marshalling;

import java.util.Collection;
import java.util.List;
import xades4j.properties.data.CertificateValuesData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.xml.bind.xades.XmlCertificateValuesType;
import xades4j.xml.bind.xades.XmlEncapsulatedPKIDataType;
import xades4j.xml.bind.xades.XmlUnsignedPropertiesType;

/**
 *
 * @author Luís
 */
class ToXmlCertificateValuesConverter implements UnsignedPropertyDataToXmlConverter
{
    @Override
    public void convertIntoObjectTree(
            PropertyDataObject propData,
            XmlUnsignedPropertiesType xmlProps)
    {
        Collection<byte[]> certValues = ((CertificateValuesData)propData).getData();

        XmlCertificateValuesType xmlCertValues = new XmlCertificateValuesType();
        List xmlCerts = xmlCertValues.getEncapsulatedX509CertificateOrOtherCertificate();

        for (byte[] encodCer : certValues)
        {
            XmlEncapsulatedPKIDataType xmlEncodCert = new XmlEncapsulatedPKIDataType();
            xmlEncodCert.setValue(encodCer);
            xmlCerts.add(xmlEncodCert);
        }

        xmlProps.getUnsignedSignatureProperties().setCertificateValues(xmlCertValues);
    }
}
