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
 * The {@code RevocationValues} property is an optional unsigned property and qualifies
 * the XML signature. There is at most one occurence of this property in the signature.
 * <p>
 * The {@code RevocationValues} property is used to hold the values of the revocation
 * information which are to be shipped with the electronic signature.
 * @author Luís
 */
public class RevocationValuesProperty extends UnsignedSignatureProperty
{
    public static final String PROP_NAME = "RevocationValues";
    private final Collection<X509CRL> crls;

    public RevocationValuesProperty(Collection<X509CRL> crls)
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
