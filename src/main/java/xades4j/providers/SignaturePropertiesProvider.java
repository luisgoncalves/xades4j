/*
 *  XAdES4j - A Java library for generation and verification of XAdES signatures.
 *  Copyright (C) 2010 Luis Goncalves.
 * 
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation; either version 2 of the License, or any later version.
 * 
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 *  Place, Suite 330, Boston, MA 02111-1307 USA
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
