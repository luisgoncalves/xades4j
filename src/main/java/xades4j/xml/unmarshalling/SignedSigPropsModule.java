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
import xades4j.xml.bind.xades.XmlSignedPropertiesType;
import xades4j.xml.bind.xades.XmlSignedSignaturePropertiesType;

/**
 *
 * @author Luís
 */
class SignedSigPropsModule extends UnmarshallerModule<XmlSignedSignaturePropertiesType>
{
    SignedSigPropsModule()
    {
        super(6);
        super.addConverter(new FromXmlSigningCertificateConverter());
        super.addConverter(new FromXmlSigningTimeConverter());
        super.addConverter(new FromXmlSignerRoleConverter());
        super.addConverter(new FromXmlSignatureProdPlaceConverter());
        super.addConverter(new FromXmlSignaturePolicyConverter());
    }

    @Override
    protected XmlSignedSignaturePropertiesType getXmlProps(
            XmlQualifyingPropertiesType xmlQualifProps)
    {
        XmlSignedPropertiesType xmlSignedProps = xmlQualifProps.getSignedProperties();
        return null == xmlSignedProps ? null : xmlSignedProps.getSignedSignatureProperties();
    }

    @Override
    protected Element getProps(Element qualifProps)
    {
        throw new UnsupportedOperationException("Shouldn't be invoked");
    }

    @Override
    protected void setAcceptUnknownProperties(boolean accept)
    {
        // The schema for SignedSignatureProperties is closed. New properties are
        // not allowed. An error will occur in JAXB if unknown elements are present.
    }
}
