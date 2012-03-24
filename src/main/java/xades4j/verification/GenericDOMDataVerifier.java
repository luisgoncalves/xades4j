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
package xades4j.verification;

import com.google.inject.Inject;
import java.util.Map;
import javax.xml.namespace.QName;
import org.w3c.dom.Element;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.GenericDOMData;

/**
 *
 * @author Luís
 */
class GenericDOMDataVerifier implements QualifyingPropertyVerifier<GenericDOMData>
{
    private final Map<QName,QualifyingPropertyVerifier> customElemVerifiers;

    @Inject
    GenericDOMDataVerifier(Map<QName, QualifyingPropertyVerifier> customElemVerifiers)
    {
        this.customElemVerifiers = customElemVerifiers;
    }

    @Override
    public QualifyingProperty verify(
            GenericDOMData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        final Element propElem = propData.getPropertyElement();
        QName propElemQName = new QName(propElem.getNamespaceURI(), propElem.getLocalName());

        QualifyingPropertyVerifier propVerifier = customElemVerifiers.get(propElemQName);
        if (null == propVerifier)
            throw new InvalidPropertyException()
            {
                @Override
                protected String getVerificationMessage()
                {
                    return "Verifier not available for " + getPropertyName();
                }

                @Override
                public String getPropertyName()
                {
                    return propElem.getLocalName();
                }
            };

        return propVerifier.verify(propData, ctx);
    }
}
