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
package xades4j.providers;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Container of validation data (certificates and corresponding CRLs).
 * <p>
 * Contains the full certification chain, starting with the signing certificate
 * and endind with the trust-anchor.
 * @author Luís
 */
public class ValidationData
{
    private final List<X509Certificate> certs;
    private final Collection<X509CRL> crls;

    /**
     * @param crls the CRLs used to validate the certificates in {@code certs}. Might be {@code null}.
     * @throws NullPointerException if {@code certs} is {@code null}
     * @throws IllegalArgumentException if {@code certs} is empty
     */
    public ValidationData(
            List<X509Certificate> certs,
            Collection<X509CRL> crls)
    {
        if (null == certs)
            throw new NullPointerException("Null cert path");
        if (certs.isEmpty())
            throw new IllegalArgumentException("Empty cert path");

        this.certs = Collections.unmodifiableList(certs);
        if (null == crls)
            this.crls = Collections.emptyList();
        else
            this.crls = Collections.unmodifiableCollection(crls);
    }

    public ValidationData(List<X509Certificate> certs)
    {
        this(certs, null);
    }

    public List<X509Certificate> getCerts()
    {
        return certs;
    }

    public Collection<X509CRL> getCrls()
    {
        return crls;
    }
}
