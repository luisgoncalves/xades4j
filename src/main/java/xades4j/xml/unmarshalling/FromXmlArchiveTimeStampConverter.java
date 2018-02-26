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

import xades4j.algorithms.Algorithm;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.data.ArchiveTimeStampData;
import xades4j.xml.bind.xades.XmlUnsignedSignaturePropertiesType;

public class FromXmlArchiveTimeStampConverter extends
        FromXmlBaseTimeStampConverter<ArchiveTimeStampData>
        implements UnsignedSigPropFromXmlConv
{

    public FromXmlArchiveTimeStampConverter()
    {
        super(ArchiveTimeStampProperty.PROP_NAME);
    }

    @Override
    public void convertFromObjectTree(
            XmlUnsignedSignaturePropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector)
            throws PropertyUnmarshalException
    {
        super.convertTimeStamps(xmlProps.getArchiveTimeStamp(),
                propertyDataCollector);
    }

    @Override
    protected ArchiveTimeStampData createTSData(Algorithm c14n)
    {
        return new ArchiveTimeStampData(c14n);
    }

    @Override
    protected void setTSData(ArchiveTimeStampData tsData,
            QualifyingPropertiesDataCollector propertyDataCollector)
    {
        propertyDataCollector.addArchiveTimeStamp(tsData);
    }

}
