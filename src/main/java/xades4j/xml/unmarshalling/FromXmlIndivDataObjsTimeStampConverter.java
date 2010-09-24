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
package xades4j.xml.unmarshalling;

import java.util.List;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.xml.bind.xades.XmlIncludeType;
import xades4j.xml.bind.xades.XmlSignedDataObjectPropertiesType;
import xades4j.xml.bind.xades.XmlXAdESTimeStampType;

/**
 *
 * @author Luís
 */
class FromXmlIndivDataObjsTimeStampConverter
        extends FromXmlBaseTimeStampConverter
        implements SignedDataObjPropFromXmlConv
{
    @Override
    public void convertFromObjectTree(
            XmlSignedDataObjectPropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        super.convertTimeStamps(
                xmlProps.getIndividualDataObjectsTimeStamp(),
                propertyDataCollector,
                IndividualDataObjsTimeStampProperty.PROP_NAME);
    }

    @Override
    protected BaseXAdESTimeStampData createTSData(String canonAlgUri)
    {
        return new IndividualDataObjsTimeStampData(canonAlgUri);
    }

    @Override
    protected void doSpecificConvert(
            XmlXAdESTimeStampType xmlTS,
            BaseXAdESTimeStampData tsData) throws PropertyUnmarshalException
    {
        IndividualDataObjsTimeStampData indivDOTSData = (IndividualDataObjsTimeStampData)tsData;

        List<XmlIncludeType> includes = xmlTS.getInclude();
        for (XmlIncludeType xmlInc : includes)
        {
            indivDOTSData.addInclude(xmlInc.getURI());
        }
    }

    @Override
    protected void setTSData(
            BaseXAdESTimeStampData tsData,
            QualifyingPropertiesDataCollector propertyDataCollector)
    {
        propertyDataCollector.addIndividualDataObjsTimeStamp((IndividualDataObjsTimeStampData)tsData);
    }
}
