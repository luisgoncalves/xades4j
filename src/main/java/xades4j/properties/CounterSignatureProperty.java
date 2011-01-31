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
package xades4j.properties;

import xades4j.production.XadesSigner;
import xades4j.verification.XAdESVerificationResult;

/**
 * Represents the {@code CounterSignature} unsigned signature property. A XAdES
 * signature may have more one {@code CounterSignature} properties.
 * <p>
 * This property is added to the signature through {@link xades4j.providers.SignaturePropertiesProvider}.
 * <p>
 * <b>Limitation</b>: counter signatures must be XAdES signatures.
 *
 * @author Luís
 */
public final class CounterSignatureProperty extends UnsignedSignatureProperty
{
    public static final String COUNTER_SIGNATURE_TYPE_URI = "http://uri.etsi.org/01903#CountersignedSignature",
            PROP_NAME = "CounterSignature";
    private XadesSigner counterSigSigner;
    private XAdESVerificationResult verificationResult;

    /**
     * @param counterSigSigner the signer that will be used to generate the counter signature
     * @throws NullPointerException if {@code counterSigSigner} is {@code null}
     */
    public CounterSignatureProperty(XadesSigner counterSigSigner)
    {
        if (null == counterSigSigner)
            throw new NullPointerException("Signer for counter signature cannot be null");
        this.counterSigSigner = counterSigSigner;
    }

    /**
     * 
     * @param verificationResult the result of counter signature verification
     */
    public CounterSignatureProperty(XAdESVerificationResult verificationResult)
    {
        this.verificationResult = verificationResult;
    }

    /**
     * Gets the signer that is used to generate the counter signature or {@code null}.
     * @return the signer
     */
    public XadesSigner getCounterSigSigner()
    {
        return counterSigSigner;
    }

    /**
     * Gets the result of counter signature verification or {@code null} if the property
     * wasn't verified.
     * @return the verification result
     */
    public XAdESVerificationResult getVerificationResult()
    {
        return verificationResult;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
