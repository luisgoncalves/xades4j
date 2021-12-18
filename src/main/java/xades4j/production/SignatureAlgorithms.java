/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2021 Luis Goncalves.
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
package xades4j.production;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.CanonicalXMLWithoutComments;
import xades4j.algorithms.GenericAlgorithm;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration of the algorithms used for signature production.
 * <p>
 * The defaults are:
 * <ul>
 *     <li>Signature: RSA(RSA_SHA256), DSA(DSA_SHA1), EC(ECDSA_SHA256)</li>
 *     <li>Canonicalization: Canonical XML 1.0 without comments</li>
 *     <li>Digest: SHA256</li>
 * </ul>
 *
 * @see XadesSigningProfile#withSignatureAlgorithms(SignatureAlgorithms)
 */
public final class SignatureAlgorithms
{
    private final Map<String, Algorithm> keyAlgToSignatureAlg = new HashMap<>();
    private Algorithm canonicalizationAlgorithmForSignature = new CanonicalXMLWithoutComments();
    private Algorithm canonicalizationAlgorithmForTimeStampProperties = new CanonicalXMLWithoutComments();
    private String digestAlgorithmForDataObjectReferences = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
    private String digestAlgorithmForReferenceProperties = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
    private String digestAlgorithmForTimeStampProperties = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;

    public SignatureAlgorithms()
    {
        keyAlgToSignatureAlg.put("DSA", new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_DSA));
        keyAlgToSignatureAlg.put("RSA", new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256));
        keyAlgToSignatureAlg.put("EC", new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256));
    }

    /**
     * Set the signature algorithm to be used when the signing key has the given key algorithm.
     *
     * @param keyAlgorithmName   the key's algorithm name as defined in JCA standard algorithm names
     * @param signatureAlgorithm the signature algorithm
     * @return the current instance
     */
    public SignatureAlgorithms withSignatureAlgorithm(String keyAlgorithmName, String signatureAlgorithm)
    {
        keyAlgToSignatureAlg.put(keyAlgorithmName, new GenericAlgorithm(signatureAlgorithm));
        return this;
    }

    Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException
    {
        var algorithm = keyAlgToSignatureAlg.get(keyAlgorithmName);

        if (algorithm == null)
        {
            throw new UnsupportedAlgorithmException("Unsupported signature algorithm", keyAlgorithmName);
        }

        return algorithm;
    }

    /**
     * Sets the canonicalization algorithm to be used in the {@code Signature}.
     *
     * @param algorithm the algorithm
     * @return the current instance
     */
    public SignatureAlgorithms withCanonicalizationAlgorithmForSignature(Algorithm algorithm)
    {
        this.canonicalizationAlgorithmForSignature = algorithm;
        return this;
    }

    Algorithm getCanonicalizationAlgorithmForSignature()
    {
        return this.canonicalizationAlgorithmForSignature;
    }

    /**
     * Sets the canonicalization algorithm to be used in the qualifying properties that contain time-stamp tokens.
     *
     * @param algorithm the algorithm
     * @return the current instance
     */
    public SignatureAlgorithms withCanonicalizationAlgorithmForTimeStampProperties(Algorithm algorithm)
    {
        this.canonicalizationAlgorithmForTimeStampProperties = algorithm;
        return this;
    }

    Algorithm getCanonicalizationAlgorithmForTimeStampProperties()
    {
        return this.canonicalizationAlgorithmForTimeStampProperties;
    }

    /**
     * Sets the digest algorithm to be used in the data object {@code Reference}s.
     *
     * @param algorithm the algorithm
     * @return the current instance
     */
    public SignatureAlgorithms withDigestAlgorithmForDataObjectReferences(String algorithm)
    {
        this.digestAlgorithmForDataObjectReferences = algorithm;
        return this;
    }

    String getDigestAlgorithmForDataObjectReferences()
    {
        return this.digestAlgorithmForDataObjectReferences;
    }

    /**
     * Sets the digest algorithm to be used in the qualifying properties that contain references to certificates,
     * CRLs and so on.
     *
     * @param algorithm the algorithm
     * @return the current instance
     */
    public SignatureAlgorithms withDigestAlgorithmForReferenceProperties(String algorithm)
    {
        this.digestAlgorithmForReferenceProperties = algorithm;
        return this;
    }

    String getDigestAlgorithmForReferenceProperties()
    {
        return this.digestAlgorithmForReferenceProperties;
    }

    /**
     * Sets the digest algorithm to be used in the qualifying properties that contain time-stamp tokens.
     *
     * @param algorithm the algorithm
     * @return the current instance
     */
    public SignatureAlgorithms withDigestAlgorithmForTimeStampProperties(String algorithm)
    {
        this.digestAlgorithmForTimeStampProperties = algorithm;
        return this;
    }

    String getDigestAlgorithmForTimeStampProperties()
    {
        return this.digestAlgorithmForTimeStampProperties;
    }
}
