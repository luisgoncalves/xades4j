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
package xades4j.verification;

import com.google.inject.Inject;
import com.google.inject.Injector;
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
    private final Injector injector;
    private final Map<QName, Class<? extends QualifyingPropertyVerifier>> customElemVerifiers;

    @Inject
    GenericDOMDataVerifier(
            Injector injector,
            Map<QName, Class<? extends QualifyingPropertyVerifier>> customElemVerifiers)
    {
        this.injector = injector;
        this.customElemVerifiers = customElemVerifiers;
    }

    @Override
    public QualifyingProperty verify(
            GenericDOMData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        final Element propElem = propData.getPropertyElement();
        QName propElemQName = new QName(propElem.getNamespaceURI(), propElem.getLocalName());

        Class<? extends QualifyingPropertyVerifier> propVerifier = customElemVerifiers.get(propElemQName);
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

        return injector.getInstance(propVerifier).verify(propData, ctx);
    }
}
