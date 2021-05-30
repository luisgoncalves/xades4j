/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2021 Luis Goncalves.
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
package xades4j.production;

import xades4j.properties.DataObjectDesc;

import java.util.Collection;
import java.util.LinkedHashSet;

/**
 * Represents a {@code ds:Manifest} that will be enveloped in a {@code ds:Object} contained in the signature. The
 * {@code ds:Manifest} will be covered by a {@code ds:Reference} so that it is actually included in the signature.
 * The library handles the generation of the digests for the references contained in the manifest.
 *
 * @see DataObjectDesc
 * @see DataObjectReference
 *
 * @author Luís
 */
public final class EnvelopedManifest extends DataObjectDesc
{
    private final Collection<DataObjectDesc> dataObjs;

    public EnvelopedManifest()
    {
        this.dataObjs = new LinkedHashSet<DataObjectDesc>(2);
    }

    /**
     * Adds a new child signed data object to the current instance.
     * @param object the signed data object
     * @return the current instance
     */
    public EnvelopedManifest withSignedDataObject(DataObjectDesc object)
    {
        if (null == object)
        {
            throw new NullPointerException("Signed object description cannot be null");
        }

        if (!this.dataObjs.add(object))
        {
            throw new IllegalStateException("Data object description was already added");
        }
        return this;
    }

    Collection<DataObjectDesc> getDataObjects()
    {
        return this.dataObjs;
    }
}
