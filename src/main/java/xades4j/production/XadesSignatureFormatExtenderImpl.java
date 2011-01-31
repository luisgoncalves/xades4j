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
import xades4j.providers.AlgorithmsProvider;
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
    private final AlgorithmsProvider algorithmsProvider;

    @Inject
    XadesSignatureFormatExtenderImpl(
            PropertiesDataObjectsGenerator propsDataObjectsGenerator,
            UnsignedPropertiesMarshaller unsignedPropsMarshaller,
            AlgorithmsProvider algorithmsProvider)
    {
        this.propsDataObjectsGenerator = propsDataObjectsGenerator;
        this.unsignedPropsMarshaller = unsignedPropsMarshaller;
        this.algorithmsProvider = algorithmsProvider;
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

        SigAndDataObjsPropertiesData propsData = propsDataObjectsGenerator.generateUnsignedPropertiesData(
                props,
                new PropertiesDataGenerationContext(sig, algorithmsProvider));
        Element qualifProps = DOMHelper.getFirstDescendant(
                sig.getElement(),
                QualifyingProperty.XADES_XMLNS, QualifyingProperty.QUALIFYING_PROPS_TAG);

        // A little style trick to have nice prefixes.
        if(null == sig.getDocument().lookupPrefix(QualifyingProperty.XADESV141_XMLNS))
            qualifProps.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xades141", QualifyingProperty.XADESV141_XMLNS);

        unsignedPropsMarshaller.marshal(propsData, null, qualifProps);
    }
}
