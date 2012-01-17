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
package xades4j.xml.marshalling;

import java.util.Collection;
import java.util.List;
import org.w3c.dom.Document;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.RevocationValuesData;
import xades4j.xml.bind.xades.XmlCRLValuesType;
import xades4j.xml.bind.xades.XmlEncapsulatedPKIDataType;
import xades4j.xml.bind.xades.XmlRevocationValuesType;
import xades4j.xml.bind.xades.XmlUnsignedPropertiesType;

/**
 *
 * @author Luís
 */
class ToXmlRevocationValuesConverter implements UnsignedPropertyDataToXmlConverter
{
    @Override
    public void convertIntoObjectTree(
            PropertyDataObject propData,
            XmlUnsignedPropertiesType xmlProps,
            Document doc)
    {
        Collection<byte[]> crlValues = ((RevocationValuesData)propData).getData();

        XmlRevocationValuesType xmlRevocValues = new XmlRevocationValuesType();
        XmlCRLValuesType xmlCRLValues = new XmlCRLValuesType();
        xmlRevocValues.setCRLValues(xmlCRLValues);

        List xmlCRLs = xmlCRLValues.getEncapsulatedCRLValue();

        for (byte[] encodCrl : crlValues)
        {
            XmlEncapsulatedPKIDataType xmlEncodCert = new XmlEncapsulatedPKIDataType();
            xmlEncodCert.setValue(encodCrl);
            xmlCRLs.add(xmlEncodCert);
        }

        xmlProps.getUnsignedSignatureProperties().setRevocationValues(xmlRevocValues);
    }
}
