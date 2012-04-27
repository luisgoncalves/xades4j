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
package xades4j.production;

import xades4j.properties.UnsignedProperties;
import com.google.inject.Inject;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import xades4j.properties.QualifyingProperty;
import xades4j.XAdES4jException;
import xades4j.properties.data.SigAndDataObjsPropertiesData;
import xades4j.utils.DOMHelper;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;

/**
 *
 * @author Luís
 */
class XadesSignatureFormatExtenderImpl implements XadesSignatureFormatExtender
{
    static
    {
        Init.initXMLSec();
    }
    private final PropertiesDataObjectsGenerator propsDataObjectsGenerator;
    private final UnsignedPropertiesMarshaller unsignedPropsMarshaller;

    @Inject
    XadesSignatureFormatExtenderImpl(
            PropertiesDataObjectsGenerator propsDataObjectsGenerator,
            UnsignedPropertiesMarshaller unsignedPropsMarshaller)
    {
        this.propsDataObjectsGenerator = propsDataObjectsGenerator;
        this.unsignedPropsMarshaller = unsignedPropsMarshaller;
    }

    @Override
    public void enrichSignature(
            XMLSignature sig,
            UnsignedProperties props) throws XAdES4jException
    {
        if (props.isEmpty())
            return;
        if (!props.getDataObjProps().isEmpty())
            throw new NullPointerException();

        Element qualifProps = DOMHelper.getFirstDescendant(
                sig.getElement(),
                QualifyingProperty.XADES_XMLNS, QualifyingProperty.QUALIFYING_PROPS_TAG);
        if(null == qualifProps)
        {
            throw new IllegalArgumentException("Couldn't find XAdES QualifyingProperties");
        }

        Element signedProps = DOMHelper.getFirstChildElement(qualifProps);
        if (signedProps != null
            && signedProps.getLocalName().equals(QualifyingProperty.SIGNED_PROPS_TAG)
            && signedProps.getNamespaceURI().equals(QualifyingProperty.XADES_XMLNS))
        {
            // Register the SignedProperties XML ID.
            DOMHelper.useIdAsXmlId(signedProps);
        }

        SigAndDataObjsPropertiesData propsData = propsDataObjectsGenerator.generateUnsignedPropertiesData(
                props,
                new PropertiesDataGenerationContext(sig));
        
        // A little style trick to have nice prefixes.
        if(null == sig.getDocument().lookupPrefix(QualifyingProperty.XADESV141_XMLNS))
            qualifProps.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xades141", QualifyingProperty.XADESV141_XMLNS);

        unsignedPropsMarshaller.marshal(propsData, qualifProps);
    }
}
