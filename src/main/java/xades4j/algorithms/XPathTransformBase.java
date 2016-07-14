/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2014 Luis Goncalves.
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

import java.util.Map;
import xades4j.utils.CollectionUtils;

/**
 *
 * @author Luís
 */
public abstract class XPathTransformBase extends Algorithm
{
    private Map<String, String> namespaces;

    protected XPathTransformBase(String uri) {
        super(uri);
    }

    protected void addNamespace(String prefix, String namespace) 
    {
        if (null == prefix || prefix.isEmpty())
            throw new NullPointerException("Prefix cannot be null nor empty");
        if (null == namespace || namespace.isEmpty())
            throw new NullPointerException("Namespace cannot be null nor empty");
        
        namespaces = CollectionUtils.newIfNull(namespaces, 2);
        namespaces.put(prefix, namespace);
    }
    
    public Map<String, String> getNamespaces()
    {
        return CollectionUtils.emptyIfNull(namespaces);
    }
}
