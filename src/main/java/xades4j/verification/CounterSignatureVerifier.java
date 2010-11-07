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
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.XAdES4jException;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.GenericDOMData;
import xades4j.utils.DOMHelper;

/**
 * XAdES section G.2.2.7
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


        XAdESVerificationResult res;
        try
        {
            Element sigElem = DOMHelper.getFirstChildElement(propData.getPropertyElement());
            res = verifier.verify(sigElem);
        } catch (XAdES4jException ex)
        {
            throw new CounterSignatureXadesVerificationException(ex);
        }

        // "Check that the enclosed signature correctly references the ds:SignatureValue
        // present in the countersigned XAdES signature."

        Node targetSigValueElem = ctx.getSignature().getElement().getElementsByTagNameNS(
                Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE).item(0);

        try
        {
            SignedInfo si = res.getXmlSignature().getSignedInfo();
            for (int i = 0; i < si.getLength(); i++)
            {
                Reference r = si.item(i);
                if (r.getContentsAfterTransformation().getSubNode() == targetSigValueElem)
                    // The signature references the SignatureValue element.
                    return new CounterSignatureProperty(res);
            }
            throw new CounterSignatureSigValueRefException();
        } catch (XMLSecurityException e)
        {
            // Shouldn't happen because the signature was already verified.
            throw new CounterSignatureVerificationException(e.getMessage());
        }
    }
}
