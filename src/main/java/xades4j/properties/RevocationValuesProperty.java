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
