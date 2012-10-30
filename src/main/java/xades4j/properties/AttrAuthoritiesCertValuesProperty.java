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

import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * The {@code AttrAuthoritiesCertValues} is an optional unsigned property and qualifies
 * the XML signatures. There can be at most one occurrence of this property in the
 * signature.
 * <p>
 * This element should have the full set of certificates that are needed to verify
 * time stamps in {@code SignatureTimeStamp}, {@code SigAndRefsTimeStamp} and
 * {@code RefsOnlyTimeStamp}.
 * This property is optional part of XAdES-X-L form.
 * @author Hubert Kario
 */
public final class AttrAuthoritiesCertValuesProperty extends UnsignedSignatureProperty
{

    public static final String PROP_NAME = "AttrAuthoritiesCertValues";
    private final Collection<X509Certificate> certificates;

    public AttrAuthoritiesCertValuesProperty(Collection<X509Certificate> certificates)
    {
        if (null == certificates)
            throw new NullPointerException();
        this.certificates = certificates;
    }

    public Collection<X509Certificate> getCertificates()
    {
        return certificates;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
