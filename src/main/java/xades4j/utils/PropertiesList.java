/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import xades4j.properties.PropertyTargetException;

/**
 * A generic bag of properties used to store properties that apply to a specific target
 * (data object descriptions, signature properties collector.
 *
 * @author Hubert Kario
 */
public class PropertiesList<T>
{
    List<T> properties;
    Set<Class<?>> classes;

    /**
     * Initializes the property bag with the given number of different initial property
     * types.
     * <p>
     * The order in which the properties are added is maintained.
     * @param initialNPropTypes the initial number of different property types.
     */
    public PropertiesList(int initialNPropTypes)
    {
        this.properties = new ArrayList<T>(initialNPropTypes);
        this.classes = new HashSet<Class<?>>();
    }

    /**
     * Puts a property in the bag. The put operation doesn't allow repeated property
     * types. If a property of this <i>type</i> was previously added an exception is
     * thrown.
     *
     * @param prop the property
     *
     * @throws NullPointerException if {@code prop} is {@code null}
     * @throws PropertyTargetException if the given property type is already present in
     *                              the bag
     */
    public void put(T prop)
    {
        if (prop == null)
            throw new NullPointerException("Property cannot be null");

        if(classes.contains(prop.getClass()))
            throw new PropertyTargetException(String.format(
                    "A property of type %s was already added",
                    prop.getClass().getSimpleName()));

        classes.add(prop.getClass());
        properties.add(prop);
    }

    /**
     * Adds a property to the bag. The add operation allows multiple properties of the
     * same type and repeated instances.
     *
     * @param prop the property
     * @throws NullPointerExceptino if {@code prop} is {@code null}
     */
    public void add(T prop)
    {
        if (prop == null)
            throw new NullPointerException("Property cannot be null");

        if (!classes.contains(prop.getClass()))
            classes.add(prop.getClass());
        properties.add(prop);
    }

    /**
     * Removes a property from the bag.
     *
     * @param prop the property to be removed
     * @throws NullPointerException if the property is {@code null}
     * @throws IllegalStateException if the property is not present
     */
    public void remove(T prop)
    {
        if (prop == null)
            throw new NullPointerException("Property cannot be null");

        if (!classes.remove(prop.getClass()))
            throw new IllegalStateException("Property not present");
        if (!properties.remove(prop))
            throw new IllegalStateException("Property not present");
    }

    /**
     * Indicates whatever the bag has any properties
     * @return {@code true} if the bag has no properties
     */
    public boolean isEmpty()
    {
        return properties.isEmpty();
    }

    /**
     * Gets the properties in the bag
     * @return unmodifiable list of properties
     */
    public List<T> getProperties()
    {
        if (properties.isEmpty())
            return Collections.emptyList();

        return Collections.unmodifiableList(properties);
    }

    public int size()
    {
        return properties.size();
    }
}
