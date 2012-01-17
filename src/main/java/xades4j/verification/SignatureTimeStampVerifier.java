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
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.utils.DOMHelper;
import xades4j.utils.TimeStampDigestInputFactory;

/**
 * XAdES section G.2.2.16.1.3
 * @author Luís
 */
class SignatureTimeStampVerifier extends TimeStampVerifierBase<SignatureTimeStampData>
{
    @Inject
    public SignatureTimeStampVerifier(
            TimeStampVerificationProvider timeStampVerifier,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(timeStampVerifier, timeStampDigestInputFactory, SignatureTimeStampProperty.PROP_NAME);
    }

    @Override
    protected QualifyingProperty addPropSpecificTimeStampInputAndCreateProperty(
            SignatureTimeStampData propData,
            TimeStampDigestInput digestInput,
            QualifyingPropertyVerificationContext ctx) throws CannotAddDataToDigestInputException
    {
        Element sigValueElem = DOMHelper.getFirstDescendant(
            ctx.getSignature().getElement(),
            Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);
        digestInput.addNode(sigValueElem);
        return new SignatureTimeStampProperty();
    }
}
