/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS
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
 * The {@code AttributeRevocationValues} property is an optional unsigned property and
 * qualifies the XML signature. There is at most one occurrence of this property in the
 * signature.
 * <p>
 * The {@code AttributeRevocationValues} property is used to hold the values of revocation
 * information which are needed to check validity of TSA certificates in TimeStamps.
 *
 * @author Hubert Kario
 *
 */
public class AttributeRevocationValuesProperty extends
        UnsignedSignatureProperty
{
    public static final String PROP_NAME = "AttributeRevocationValues";
    private final Collection<X509CRL> crls;

    public AttributeRevocationValuesProperty(Collection<X509CRL> crls)
    {
        if (crls == null)
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
