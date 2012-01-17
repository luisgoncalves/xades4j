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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Provides some utility methods over collections.
 * @author Luís
 */
public class CollectionUtils
{
    /**
     * Get a collection with the specified initial size if the given collection is {@code null}.
     * The returned collection, if new, will support the {@code remove} operation.
     * @param c the collection to be tested
     * @param size the initial size of the returned collection, if new
     * @return a new collection or {@code c} if it is not {@code null}
     */
    public static <T> Collection<T> newIfNull(Collection<T> c, int size)
    {
        if (null == c)
            c = new ArrayList<T>(size);
        return c;
    }

    /**
     * Same as {@code newIfNull} but for maps.
     * @param m the map to be tested
     * @param size the initial size of the returned map, if new
     * @return a new map or {@code m} if it is not {@code null}
     */
    public static <TK, TV> Map<TK, TV> newIfNull(
            Map<TK, TV> m, int size)
    {
        if (null == m)
            m = new HashMap<TK, TV>(size);
        return m;
    }

    /**
     * Get a set with the specified initial size if the given set is {@code null}.
     * @param c the collection to be tested
     * @param size the initial size of the returned collection, if new
     * @return a new collection or {@code c} if it is not {@code null}
     */
//    public static <T> Set<T> newIfNull(Set<T> s, int size)
//    {
//        if (null == s)
//            s = new HashSet<T>(size);
//        return s;
//    }
    /**
     * Get an empty collection if the given collection is {@code null}.
     * The returned collection, if new, is immutable.
     * @param c the collection to be tested
     * @return a new empty collection or {@code c} if it is not null
     */
    public static <T> Collection<T> emptyIfNull(Collection<T> c)
    {
        if (null == c)
            c = Collections.emptyList();
        return c;
    }

    public static <TK, TV> Map<TK, TV> emptyIfNull(Map<TK, TV> m)
    {
        if (null == m)
            m = Collections.emptyMap();
        return m;
    }

    public static <T> Collection<T> cloneOrEmptyIfNull(Collection<T> c)
    {
        if (null == c)
            c = new ArrayList<T>(0);
        else
            c = new ArrayList<T>(c);
        return c;
    }

    public static <TK, TV> Map<TK, TV> cloneOrEmptyIfNull(Map<TK, TV> m)
    {
        if (null == m)
            m = new HashMap<TK, TV>(0);
        else
            m = new HashMap<TK, TV>(m);
        return m;
    }

    /**
     * Indicates whether a collection is {@code null} or empty.
     * @param c the collection to be tested
     * @return {@code true} if the collection is {@code null} or empty
     */
    public static <T> boolean nullOrEmpty(Collection<T> c)
    {
        return null == c || c.isEmpty();
    }

    public interface Predicate<T>
    {
        public boolean verifiedBy(T elem);
    }

    public static <T> List<T> filter(Collection<T> c, Predicate<T> p)
    {
        List<T> filtered = new ArrayList<T>();
        for (T e : c)
        {
            if (p.verifiedBy(e))
                filtered.add(e);
        }
        return filtered;
    }

    public interface Projector<T1, T2>
    {
        public T2 project(T1 e);
    }

    public static <TSrc, TDest> List<TDest> project(
            Collection<TSrc> c,
            Projector<TSrc, TDest> p)
    {
        List<TDest> projected = new ArrayList<TDest>();
        for (TSrc e : c)
        {
            projected.add(p.project(e));
        }
        return projected;
    }

    public static<T, T1 extends T> List<T1> filterByType(Collection<T> c, final Class<T1> clazz){
        return project(
                filter(c,new Predicate<T>()
                {
                    @Override
                    public boolean verifiedBy(T elem)
                    {
                        return clazz.isAssignableFrom(elem.getClass());
                    }
                }),
                new Projector<T, T1>()
                {
                    @Override
                    public T1 project(T e)
                    {
                        return (T1)e;
                    }
                });
    }
}
