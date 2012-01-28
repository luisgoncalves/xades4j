/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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

import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.algorithms.Algorithm;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.xml.bind.xades.XmlEncapsulatedPKIDataType;
import xades4j.xml.bind.xades.XmlSignedPropertiesType;
import xades4j.xml.bind.xades.XmlUnsignedPropertiesType;
import xades4j.xml.bind.xades.XmlXAdESTimeStampType;
import xades4j.xml.bind.xmldsig.XmlCanonicalizationMethodType;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

abstract class ToXmlSignedTimeStampDataConverter<TData extends BaseXAdESTimeStampData>
        extends ToXmlBaseTimeStampConverter<TData, XmlSignedPropertiesType>
        implements SignedPropertyDataToXmlConverter
{

    protected ToXmlSignedTimeStampDataConverter(AlgorithmsParametersMarshallingProvider algorithmsParametersMarshallingProvider)
    {
        super(algorithmsParametersMarshallingProvider);
    }
}

abstract class ToXmlUnsignedTimeStampDataConverter<TData extends BaseXAdESTimeStampData>
        extends ToXmlBaseTimeStampConverter<TData, XmlUnsignedPropertiesType>
        implements UnsignedPropertyDataToXmlConverter
{

    protected ToXmlUnsignedTimeStampDataConverter(AlgorithmsParametersMarshallingProvider algorithmsParametersMarshallingProvider)
    {
        super(algorithmsParametersMarshallingProvider);
    }
}

abstract class ToXmlBaseTimeStampConverter<TData extends BaseXAdESTimeStampData, TXml> implements QualifyingPropertyDataToXmlConverter<TXml>
{

    private final AlgorithmsParametersMarshallingProvider algorithmsParametersMarshallingProvider;

    protected ToXmlBaseTimeStampConverter(AlgorithmsParametersMarshallingProvider algorithmsParametersMarshallingProvider)
    {
        this.algorithmsParametersMarshallingProvider = algorithmsParametersMarshallingProvider;
    }

    @Override
    public final void convertIntoObjectTree(PropertyDataObject propData, TXml xmlProps, Document doc)
    {
        TData tsData = (TData) propData;
        XmlXAdESTimeStampType xmlTimeStamp = new XmlXAdESTimeStampType();

        // Canonicalization method

        XmlCanonicalizationMethodType xmlCanon = new XmlCanonicalizationMethodType();
        xmlTimeStamp.setCanonicalizationMethod(xmlCanon);

        Algorithm c14n = tsData.getCanonicalizationAlgorithm();
        xmlCanon.setAlgorithm(c14n.getUri());
        try
        {
            List<Node> c14nParams = this.algorithmsParametersMarshallingProvider.marshalParameters(c14n, doc);
            if (c14nParams != null)
            {
                xmlCanon.getContent().addAll(c14nParams);
            }
        }
        catch (UnsupportedAlgorithmException ex)
        {
            // In the current implementation the algorithm was already used before.
            // Do not throw any specific exception for now.
            throw new IllegalArgumentException("Cannot marshall algorithm parameters", ex);
        }

        // Time-stamp tokens

        List<byte[]> tsTokens = tsData.getTimeStampTokens();
        List<Object> xmlTSTokens = xmlTimeStamp.getEncapsulatedTimeStampOrXMLTimeStamp();
        for (byte[] tsToken : tsTokens)
        {
            XmlEncapsulatedPKIDataType xmlTSTkn = new XmlEncapsulatedPKIDataType();
            xmlTSTkn.setValue(tsToken);
            xmlTSTokens.add(xmlTSTkn);
        }

        insertIntoObjectTree(xmlTimeStamp, xmlProps, tsData);
    }

    protected abstract void insertIntoObjectTree(XmlXAdESTimeStampType xmlTimeStamp, TXml xmlProps, TData propData);
}
