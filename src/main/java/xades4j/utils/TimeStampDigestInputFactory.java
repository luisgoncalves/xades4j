/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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
package xades4j.utils;

import xades4j.algorithms.Algorithm;
import xades4j.UnsupportedAlgorithmException;

/**
 * Factory for builders of timestamp inputs.
 * <p>
 * This factory is intended for use on internal components and <b>may be subject
 * to changes.</b>
 *
 * @author Luís
 */
public interface TimeStampDigestInputFactory
{
    /**
     * Creates a new builder of timestamp inputs that uses the specified canonicalization
     * algorithms. The returned builders are not thread-safe but that shouldn't
     * be a problem
     * @param c14n the canonicalization method to be used by the timestamp input when
     *              adding XML node-sets
     * @return the timestamp input builder
     * @throws UnsupportedAlgorithmException if {@code c14n} is not recognized
     * @see TimeStampDigestInput
     */
    TimeStampDigestInput newTimeStampDigestInput(Algorithm c14n) throws UnsupportedAlgorithmException;
}
