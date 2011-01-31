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
package xades4j.utils;

import java.util.Collection;
import java.util.Collections;

/**
 * Container for a pair of property collections (signature and data object).
 *
 * @author Luís
 */
public abstract class SigAndDataObjPropsPair<TSigProp, TDataObjProp>
{
    private final Collection<TSigProp> sigProps;
    private final Collection<TDataObjProp> dataObjProps;

    protected SigAndDataObjPropsPair(
            Collection<TSigProp> sigProps,
            Collection<TDataObjProp> dataObjProps)
    {
        this.sigProps = Collections.unmodifiableCollection(sigProps);
        this.dataObjProps = Collections.unmodifiableCollection(dataObjProps);
    }

    /**
     * Gets the unmodifiable collection of signature properties.
     * @return the signature properties
     */
    public Collection<TSigProp> getSigProps()
    {
        return sigProps;
    }

    /**
     * Gets the unmodifiable collection of data object properties.
     * @return the data object properties
     */
    public Collection<TDataObjProp> getDataObjProps()
    {
        return dataObjProps;
    }

    /**
     * Indicates wether the container has properties.
     * @return {@code true} if there are no signature nor data object properties
     */
    public boolean isEmpty()
    {
        return sigProps.isEmpty() && dataObjProps.isEmpty();
    }
}
