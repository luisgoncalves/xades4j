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
import org.w3c.dom.Element;
import xades4j.XAdES4jException;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.GenericDOMData;
import xades4j.utils.DOMHelper;

/**
 *
 * @author Luís
 */
class CounterSignatureVerifier implements QualifyingPropertyVerifier<GenericDOMData>
{
    private final XadesVerifier verifier;

    @Inject
    CounterSignatureVerifier(XadesVerifier verifier)
    {
        this.verifier = verifier;
    }

    @Override
    public QualifyingProperty verify(
            GenericDOMData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        Element sigElem = DOMHelper.getFirstChildElement(propData.getPropertyElement());

        try
        {
            return new CounterSignatureProperty(verifier.verify(sigElem));
        } catch (XAdES4jException ex)
        {
            throw new CounterSignatureVerificationException(ex);
        }
    }
}
