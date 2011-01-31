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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Base class for all the data object properties. This class checks target multiplicity.
 * For instance, if a property can only be applied to one data object and and attempt
 * is made to apply it to another, an exception is thrown.
 * 
 * @author Luís
 */
public abstract class DataObjectProperty implements QualifyingProperty
{
    /**
     * Represents the number of data objects that a property can be applied to.
     */
    protected static enum TargetMultiplicity
    {
        /**
         * The property applies to all the data objects in the signature. It cannot
         * be explicitly added to a data object.
         */
        ALL(0),
        /**
         * The property applies to one data object in the signature.
         */
        ONE(1),
        /**
         * The propertie applies to multiple data objects.
         */
        N(Integer.MAX_VALUE, 2);
        /**/
        private final int multiplicity, initialSize;

        private TargetMultiplicity(int mult)
        {
            this(mult, mult);
        }

        private TargetMultiplicity(int mult, int size)
        {
            this.multiplicity = mult;
            this.initialSize = size;
        }
    }
    /**/
    private final Set<DataObjectDesc> targetDataObjs;
    private final TargetMultiplicity targetMultiplicity;

    protected DataObjectProperty(TargetMultiplicity targetMultiplicity)
    {
        if(null == targetMultiplicity)
            throw new NullPointerException("Target multiplicity cannot be null");

        this.targetMultiplicity = targetMultiplicity;
        this.targetDataObjs = new HashSet<DataObjectDesc>(targetMultiplicity.initialSize);
    }

    @Override
    public final boolean isSignature()
    {
        return false;
    }

    /**
     * Registers that this property applies to the given data object. Target
     * multiplicity is checked. This method is not public because it is supposed
     * to be invoked in a controlled way from within the package.
     *
     * @param dataObj the data object description to which the property is applied
     *
     * @throws NullPointerException if {@code dataObj} is {@code null}
     * @throws PropertyTargetException if the property cannot be applied to more
     *                                  data objects or is already applied to the
     *                                  given data object
     */
    void appliesTo(DataObjectDesc dataObj)
    {
        if(null == dataObj)
            throw new NullPointerException("Data object description cannot be null");

        if (this.targetDataObjs.size() == this.targetMultiplicity.multiplicity)
            throw new PropertyTargetException("Property cannot be applied to more data objects");

        if (!this.targetDataObjs.add(dataObj))
            throw new PropertyTargetException("Property already applied to the specified data object");
    }

    /**
     * Gets the data object descriptions to which the property applies.
     * This shouldn't be called if the property has {@code TargetMultiplicity.ALL}
     * @return un unmodifiable collection of data object descriptions
     * @throws PropertyTargetException if this property wasn't applied to any data objects
     */
    public Collection<DataObjectDesc> getTargetDataObjects()
    {
        if(this.targetDataObjs.isEmpty())
            throw new PropertyTargetException("Property wasn't applied to any data objects");
        return Collections.unmodifiableCollection(this.targetDataObjs);
    }
}
