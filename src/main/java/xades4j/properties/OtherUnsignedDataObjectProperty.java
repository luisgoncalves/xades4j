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

/**
 * Base class for custom unsigned data object properties. Even though the XAdES
 * schema is closed, new properties can be included in the signature by subclassing
 * this class and using the {@link DataObjectDesc#withOtherDataObjectProperty(xades4j.properties.OtherUnsignedDataObjectProperty)
 * DataObjectDesc.withOtherDataObjectProperty} method.
 * @see xades4j.properties.DataObjectDesc
 * @see xades4j.production.SignedDataObjects
 * @author Luís
 */
public abstract class OtherUnsignedDataObjectProperty extends UnsignedDataObjectProperty
{
    /**
     * Initializes the property with the given target multiplicity.
     * @param targetMult the target multiplicity
     * @throws NullPointerException if {@code targetMult} is {@code null}
     */
    protected OtherUnsignedDataObjectProperty(TargetMultiplicity targetMult)
    {
        super(targetMult);
    }
}
