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
import org.w3c.dom.Element;
import xades4j.properties.data.GenericDOMData;
import xades4j.utils.CollectionUtils;
import xades4j.xml.bind.xades.XmlAnyType;
import xades4j.xml.bind.xades.XmlUnsignedDataObjectPropertiesType;

/**
 *
 * @author Luís
 */
class FromXmlUnknownUnsignedDataObjPropsConv implements UnsignedDataObjPropFromXmlConv
{
    private boolean acceptUnknown;

    FromXmlUnknownUnsignedDataObjPropsConv()
    {
        this.acceptUnknown = false;
    }

    void setAcceptUnknownProperties(boolean accept)
    {
        this.acceptUnknown = accept;
    }

    @Override
    public void convertFromObjectTree(
            XmlUnsignedDataObjectPropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        for (XmlAnyType xmlUnsignedDtaObjProp : xmlProps.getUnsignedDataObjectProperty())
        {
            // <xsd:complexType name="UnsignedDataObjectPropertiesType">
            //  <xsd:sequence>
            //   <xsd:element name="UnsignedDataObjectProperty" type="AnyType"
            //    maxOccurs="unbounded"/>
            //  </xsd:sequence>
            //  <xsd:attribute name="Id" type="xsd:ID" use="optional"/>
            // </xsd:complexType>
            //
            // I assumed that there is only one "top" element inside UnsignedDataObjectProperty,
            // which is the property element. The AnyType schema allows for multiple
            // elements but since the UnsignedDataObjectProperty has to be present,
            // it makes sense that it has only one child.

            List<Element> propElemContent = CollectionUtils.filterByType(
                    xmlUnsignedDtaObjProp.getContent(),
                    Element.class);

            if (!this.acceptUnknown)
                throw new PropertyUnmarshalException("Unknown properties were found", "Unknown");

            if (propElemContent.size() > 1)
                throw new PropertyUnmarshalException("Multiple children elements in UnsignedDataObjectProperty", "Unknown");

            propertyDataCollector.addGenericDOMData(
                    new GenericDOMData(propElemContent.get(0)));
        }
    }
}
