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

import org.w3c.dom.Element;
import xades4j.xml.bind.xades.XmlQualifyingPropertiesType;
import xades4j.xml.bind.xades.XmlUnsignedDataObjectPropertiesType;
import xades4j.xml.bind.xades.XmlUnsignedPropertiesType;

/**
 *
 * @author Luís
 */
class UnsignedDataObjPropsModule extends UnmarshallerModule<XmlUnsignedDataObjectPropertiesType>
{
    private final FromXmlUnknownUnsignedDataObjPropsConv unknownUnsignedDataObjPropsConv;

    UnsignedDataObjPropsModule()
    {
        super(1);
        this.unknownUnsignedDataObjPropsConv = new FromXmlUnknownUnsignedDataObjPropsConv();
        super.addConverter(unknownUnsignedDataObjPropsConv);
    }

    @Override
    protected XmlUnsignedDataObjectPropertiesType getXmlProps(
            XmlQualifyingPropertiesType xmlQualifProps)
    {
        XmlUnsignedPropertiesType xmlUnsignedProps = xmlQualifProps.getUnsignedProperties();
        return null == xmlUnsignedProps ? null : xmlUnsignedProps.getUnsignedDataObjectProperties();
    }

    @Override
    protected Element getProps(Element qualifProps)
    {
        throw new UnsupportedOperationException("Shouldn't be invoked");
    }

    @Override
    protected void setAcceptUnknownProperties(boolean accept)
    {
        this.unknownUnsignedDataObjPropsConv.setAcceptUnknownProperties(accept);
    }
}
