/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

import xades4j.algorithms.Algorithm;
import xades4j.UnsupportedAlgorithmException;

/**
 * Interface for providers of algorithms information for signature production.
 * An instance of a class implementing this interface is supplied to inner components
 * which will query the instance whenever they need information on the algorithms
 * to use (when generating {@code ds:Reference} elements, for example).
 * <p>
 * This allows the customization of the different algotihms used in the signature.
 * <p>
 * The methods on this classes must not return {@code null}.
 * <p>
 * A default implementation is provided.
 * @see xades4j.providers.impl.DefaultAlgorithmsProviderEx
 * 
 * @author Luís
 */
public interface AlgorithmsProviderEx
{

    /**
     * Gets the signature's algorithm for the given algorithm name.
     * @param keyAlgorithmName the signing key's algorithm name as defined in JCA standard algorithm names
     * @return the algorithm
     */
    Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException;

    /**
     * Gets the canonicalization algorithm to be used in the {@code Signature}.
     * @return the algorithm 
     */
    Algorithm getCanonicalizationAlgorithmForSignature();

    /**
     * Gets the canonicalization algorithm to be used in the qualifying
     * properties, when needed.
     * @return the algorithm
     */
    Algorithm getCanonicalizationAlgorithmForTimeStampProperties();

    /**
     * Gets the digest algorithm to be used in the data object {@code Reference}s.
     * @return the algorithm
     */
    String getDigestAlgorithmForDataObjsReferences();

    /**
     * Gets the digest algorithm to be used in the qualifying properties that contain
     * references to certificates, CRLs and so on.
     * @return the algorithm
     */
    String getDigestAlgorithmForReferenceProperties();

    /**
     * Gets the digest algorithm to be used in the qualifying properties that contain
     * time-stamps
     * @return the algorithm
     */
    String getDigestAlgorithmForTimeStampProperties();
}
