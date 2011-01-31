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

/**
 * Interface for providers of signature properties. This is used during signature
 * generation to collect the optional signature properties that should be added
 * to the final XAdES signature. Note that the mandatory properties in each format
 * are enforced during signature production.
 * 
 * @author Luís
 */
public interface SignaturePropertiesProvider
{
    /**
     * Provides the signature properties through a collector. This approach is used
     * instead of a series of get methods or returning two collections of properties
     * (signed and unsigned) because it results in a simpler interface for
     * implementing classes. Besides, the collector is provided by the lib, which
     * enables control of property mutiplicity.
     *
     * @param signedPropsCol the signature properties collector (a new instance
     *                      for each invocation)
     *
     * @see SignaturePropertiesCollector
     */
    public void provideProperties(SignaturePropertiesCollector signedPropsCol);
}
