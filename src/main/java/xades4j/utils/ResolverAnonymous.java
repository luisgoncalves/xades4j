/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2020 Luis Goncalves.
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

import java.io.InputStream;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;

/**
 * Resource resolver for References without an URI attribute.
 * 
 * @author luis
 */
public final class ResolverAnonymous extends ResourceResolverSpi
{
    private final InputStream data;
    
    
    public ResolverAnonymous(InputStream data)
    {
        this.data = data;
    }
    
    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException
    {
        return new XMLSignatureInput(this.data);
    }

    @Override
    public boolean engineCanResolveURI(ResourceResolverContext context)
    {
        return context.uriToResolve == null;
    }
}
