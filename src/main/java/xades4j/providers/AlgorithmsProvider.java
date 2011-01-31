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
package xades4j.providers;

import xades4j.UnsupportedAlgorithmException;

/**
 * Interface for providers of the algorithms used in the signature generation.
 * An instance of a class implementing this interface is supplied to the signer
 * which will query the instance whenever he needs an algorithm information (when
 * generating {@code ds:Reference} elements, for instance).
 * <p>
 * The methods on this classes must not return {@code null}.
 * <p>
 * This allows the customization of the different algotihms used in the signature.
 * A default implementation is provided.
 * @see xades4j.providers.impl.DefaultAlgorithmsProvider
 * @author Luís
 */
public interface AlgorithmsProvider
{
    /**
     * Gets the signature's algorithm for the given algorithm name.
     * @param keyAlgorithmName the signing key's algorithm name as defined in JCA standard algorithm names
     * @return the algorithm URI
     */
    String getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException;

    /**
     * Gets the canonicalization algorithm to be used in the {@code Signature}.
     * @return the algorithm URI
     */
    String getCanonicalizationAlgorithmForSignature();

    /**
     * Gets the canonicalization algorithm to be used in the qualifying
     * properties, when needed.
     * @return the algorithm URI
     */
    String getCanonicalizationAlgorithmForTimeStampProperties();

    /**
     * Gets the digest algorithm to be used in the data object {@code Reference}s.
     * @return the algorithm URI
     */
    String getDigestAlgorithmForDataObjsReferences();

    /**
     * Gets the digest algorithm to be used in the qualifying properties that contain
     * references to certificates, CRLs and so on.
     * @return the algorithm URI
     */
    String getDigestAlgorithmForReferenceProperties();

    /**
     * Gets the digest algorithm to be used in the qualifying properties that contain
     * time-stamps
     * @return the algorithm URI
     */
    String getDigestAlgorithmForTimeStampProperties();
}
