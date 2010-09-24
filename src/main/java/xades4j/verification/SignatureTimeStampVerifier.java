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
import java.util.Date;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.utils.DOMHelper;

/**
 * XAdES section G.2.2.16.1.3
 * @author Luís
 */
class SignatureTimeStampVerifier implements QualifyingPropertyVerifier<SignatureTimeStampData>
{
    private final TimeStampVerificationProvider timeStampVerifier;

    @Inject
    public SignatureTimeStampVerifier(
            TimeStampVerificationProvider timeStampVerifier)
    {
        this.timeStampVerifier = timeStampVerifier;
    }

    @Override
    public QualifyingProperty verify(
            SignatureTimeStampData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        Element sigValueElem = DOMHelper.getFirstDescendant(
                ctx.getSignature().getElement(),
                Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);

        TimeStampDigestInput tsDigestInput = new TimeStampDigestInput(propData.getCanonicalizationAlgorithmUri());
        try
        {
            tsDigestInput.addNode(sigValueElem);
        } catch (CannotAddDataToDigestInputException ex)
        {
            throw new TimeStampDigestInputException(SignatureTimeStampProperty.PROP_NAME);
        }

        Date time = TimeStampUtils.verifyTokens(propData, tsDigestInput, timeStampVerifier, SignatureTimeStampProperty.PROP_NAME);
        SignatureTimeStampProperty sts = new SignatureTimeStampProperty();
        sts.setTime(time);
        return sts;
    }
}
