/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2018 Luis Goncalves.
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
package xades4j.verification;

import javax.inject.Inject;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import xades4j.providers.X500NameStyleProvider;
import xades4j.utils.X500ExtensibleNameStyle;

/**
 * <b>Experimental API</b>. It may be changed or removed in future releases.
 *
 * @author luis
 */
class DistinguishedNameComparer
{
    private final X500ExtensibleNameStyle x500NameStyle;
    private final X500NameStyleProvider x500NameStyleProvider;
    
    @Inject
    DistinguishedNameComparer(X500ExtensibleNameStyle x500NameStyle, X500NameStyleProvider x500NameStyleProvider)
    {
        this.x500NameStyle = x500NameStyle;
        this.x500NameStyleProvider = x500NameStyleProvider;
    }

    /**
     * @exception IllegalArgumentException if the DN string is invalid 
     */
    boolean areEqual(X500Principal parsedDn, String stringDn)
    {
        X500Name first = X500Name.getInstance(parsedDn.getEncoded());
        X500Name second = X500Name.getInstance(this.x500NameStyle, this.x500NameStyleProvider.fromString(stringDn).getEncoded());
        return first.equals(second);
    }
}
