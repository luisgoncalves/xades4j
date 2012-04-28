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

package xades4j.algorithms;

/**
 * Represents algorithms used on the signature, such as data object transforms,
 * signature algorithms or canonicalization algorithms. Subclasses are provided
 * for some common algorithms.
 *
 * @see xades4j.providers.AlgorithmsProviderEx
 * @see xades4j.properties.DataObjectDesc#withTransform(Algorithm)
 *
 * @author Luís
 */
public abstract class Algorithm
{
    private final String uri;

    /**
     * @param uri the algorithm's URI
     */
    protected Algorithm(String uri)
    {
        this.uri = uri;
    }

    public String getUri()
    {
        return this.uri;
    }
}
