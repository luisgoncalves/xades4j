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

import java.util.ArrayList;
import java.util.Collection;
import org.w3c.dom.Element;
import xades4j.utils.CollectionUtils;
import xades4j.xml.bind.xades.XmlQualifyingPropertiesType;

/**
 * Helper class that convertes proeprties of a given type. The converters are
 * invoked only if the corresponding JAXB parent is present. This way the converters
 * don't need to be always checking that.
 * 
 * @author Luís
 */
abstract class UnmarshallerModule<TXml>
{
    private final Collection<QualifyingPropertyFromXmlConverter<TXml>> converters;
    private Collection<QualifyingPropertyFromDOMConverter> domConverters;

    protected UnmarshallerModule(int nConvs)
    {
        this.converters = new ArrayList<QualifyingPropertyFromXmlConverter<TXml>>(nConvs);
    }

    protected void addConverter(QualifyingPropertyFromXmlConverter<TXml> c)
    {
        this.converters.add(c);
    }

    protected void addConverter(QualifyingPropertyFromDOMConverter c)
    {
        this.domConverters = CollectionUtils.newIfNull(domConverters, 2);
        this.domConverters.add(c);
    }

    void convertProperties(
            XmlQualifyingPropertiesType xmlQualifProps,
            Element qualifProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        TXml xmlProps = getXmlProps(xmlQualifProps);
        if (null == xmlProps)
            return;

        for (QualifyingPropertyFromXmlConverter<TXml> conv : converters)
        {
            conv.convertFromObjectTree(xmlProps, propertyDataCollector);
        }

        if (domConverters != null)
        {
            Element props = getProps(qualifProps);
            for (QualifyingPropertyFromDOMConverter conv : domConverters)
            {
                conv.convertFromDOMTree(props, propertyDataCollector);
            }
        }
    }

    protected abstract TXml getXmlProps(
            XmlQualifyingPropertiesType xmlQualifProps);

    protected abstract Element getProps(Element qualifProps);

    protected abstract void setAcceptUnknownProperties(boolean accept);
}
