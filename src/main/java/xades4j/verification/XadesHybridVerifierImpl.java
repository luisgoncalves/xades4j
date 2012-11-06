/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
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

import java.util.Date;

import org.w3c.dom.Element;

import xades4j.XAdES4jException;
import xades4j.production.XadesSignatureFormatExtender;

public class XadesHybridVerifierImpl implements XadesVerifier
{
    @Override
    public XAdESVerificationResult verify(Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions)
            throws XAdES4jException
    {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public XAdESVerificationResult verify(Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions,
            XadesSignatureFormatExtender formatExtender, XAdESForm finalForm)
            throws XAdES4jException
    {
        // TODO Auto-generated method stub
        return null;
    }

    // used only for tests
    protected XAdESVerificationResult verify(Element signatureNode, Object object,
            XadesSignatureFormatExtender formExt, XAdESForm c, Date date)
    {
        // TODO Auto-generated method stub
        return null;
    }

}
