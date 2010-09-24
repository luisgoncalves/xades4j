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
package xades4j.properties;

import java.security.cert.X509CRL;
import java.util.Collection;

/**
 * The {@code } property contains a sequence of references to the full set of revocation
 * data that have been used in the validation of the signer and CA certificates.
 * <p>
 * This is an optional unsigned property that qualifies the signature. There is
 * at most one occurence of this property in the signature.
 * <p>
 * This property is not used directly when producing a signature. Instead, it is
 * enforced by the {@link xades4j.production.XadesSigner} producing a XAdES-C.
 * <p>
 * Only CRLs are supported.
 * @author Luís
 */
public class CompleteRevocationRefsProperty extends UnsignedSignatureProperty
{
    public static final String PROP_NAME = "CompleteRevocationRefs";
    private final Collection<X509CRL> crls;

    /**
     * Creates an instance of the property that will result in CRL references for
     * {@code crls}.
     * @param crls the set of CRLs that will have references on the property
     * @throws NullPointerException if {@code crls} is {@code null}
     */
    public CompleteRevocationRefsProperty(Collection<X509CRL> crls)
    {
        if (null == crls)
            throw new NullPointerException();
        this.crls = crls;
    }

    public Collection<X509CRL> getCrls()
    {
        return crls;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
