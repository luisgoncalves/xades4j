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
