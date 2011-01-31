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
import xades4j.xml.bind.xades.XmlUnsignedSignaturePropertiesType;

/**
 *
 * @author Luís
 */
class FromXmlUnknownUnsignedSigPropsConverter implements UnsignedSigPropFromXmlConv
{
    private boolean acceptUnknown;

    public FromXmlUnknownUnsignedSigPropsConverter()
    {
        this.acceptUnknown = false;
    }

    void setAcceptUnknownProperties(boolean accept)
    {
        this.acceptUnknown = accept;
    }

    @Override
    public void convertFromObjectTree(
            XmlUnsignedSignaturePropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        List<Object> any = xmlProps.getAny();
        if (any.size() > 0 && !this.acceptUnknown)
            throw new PropertyUnmarshalException("Unknown properties were found", "Unknown");

        for (Object anyObj : any)
        {
            if (anyObj instanceof Element)
                propertyDataCollector.addGenericDOMData(new GenericDOMData((Element)anyObj));
        }
    }
}
