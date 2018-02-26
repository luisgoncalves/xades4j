/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
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
package xades4j.production;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;

public class TestResolverSpi extends ResourceResolverSpi {

    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
        try {
            String fileName = context.uriToResolve.replace("xades4j://", "");
            return new XMLSignatureInput(new FileInputStream(new File("src/test/xml/" + fileName)));
        } catch (FileNotFoundException ex) {
            throw new ResourceResolverException(ex.getMessage(), context.uriToResolve, "src/test/xml/");
        }
    }

    @Override
    public boolean engineCanResolveURI(ResourceResolverContext context) {
        return context.attr.getValue().startsWith("xades4j:");
    }

}
