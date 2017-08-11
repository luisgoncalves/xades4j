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

import java.util.Collection;
import org.w3c.dom.Element;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.GenericDOMData;
import xades4j.utils.DOMHelper;

/**
 *
 * @author Luís
 */
class FromDOMCounterSignatureConverter implements QualifyingPropertyFromDOMConverter
{
    @Override
    public void convertFromDOMTree(
            Element props,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        Collection<Element> counterSigs = DOMHelper.getChildElementsByTagNameNS(
            props,
            QualifyingProperty.XADES_XMLNS,
            CounterSignatureProperty.PROP_NAME);
        
        for (Element counterSig : counterSigs)
        {
            propertyDataCollector.addGenericDOMData(new GenericDOMData(counterSig));
        }
    }
}
