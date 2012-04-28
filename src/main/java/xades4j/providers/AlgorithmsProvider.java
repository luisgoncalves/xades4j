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
 * @deprecated
 * This interface is deprecated and might be removed in future versions.
 * @see AlgorithmsProviderEx
 */
public interface AlgorithmsProvider
{
    /**
     * @deprecated the interface is deprecated
     */
    String getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException;

    /**
     * @deprecated the interface is deprecated
     */
    String getCanonicalizationAlgorithmForSignature();

    /**
     * @deprecated the interface is deprecated
     */
    String getCanonicalizationAlgorithmForTimeStampProperties();

    /**
     * @deprecated the interface is deprecated
     */
    String getDigestAlgorithmForDataObjsReferences();

    /**
     * @deprecated the interface is deprecated
     */
    String getDigestAlgorithmForReferenceProperties();

    /**
     * @deprecated the interface is deprecated
     */
    String getDigestAlgorithmForTimeStampProperties();
}
