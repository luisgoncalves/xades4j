/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.utils;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import xades4j.utils.CollectionUtils.Predicate;

/**
 *
 * @author Luís
 */
public class DataGetterImpl<T> implements DataGetter<T>
{
    private final Collection<T> all;
    private final Map<Class, Set<T>> allByType;

    public DataGetterImpl(Collection<T> all)
    {
        this.all = Collections.unmodifiableCollection(all);
        this.allByType = getAllByType(all);
    }

    private Map<Class, Set<T>> getAllByType(Collection<T> all)
    {
        Map<Class, Set<T>> res = new HashMap<Class, Set<T>>();

        for (T e : all)
        {
            Set<T> typeTs = res.get(e.getClass());
            if (null == typeTs)
            {
                typeTs = new HashSet<T>();
                res.put(e.getClass(), typeTs);
            }
            typeTs.add(e);
        }
        return res;
    }

    @Override
    public Collection<T> getAll()
    {
        return all;
    }

    @Override
    public <TP extends T> Collection<TP> getOfType(
            Class<TP> clazz)
    {
        return (Collection<TP>)CollectionUtils.emptyIfNull(allByType.get(clazz));
    }

    @Override
    public Collection<T> getFiltered(Predicate<T> filter)
    {
        return CollectionUtils.filter(all, filter);
    }
}
