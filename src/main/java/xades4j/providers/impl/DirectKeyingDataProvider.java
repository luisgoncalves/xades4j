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
package xades4j.providers.impl;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import xades4j.providers.KeyingDataProvider;

/**
 * An implementation of {@code KeyingDataProvider} that allows direct specification
 * of the signing key and certificate.
 * @author Luís
 */
public class DirectKeyingDataProvider implements KeyingDataProvider
{
    private final List<X509Certificate> certificates;
    private final PrivateKey key;

    public DirectKeyingDataProvider(X509Certificate certificate, PrivateKey key)
    {
        if (null == certificate || null == key)
            throw new NullPointerException("Null key or certificate");
        this.certificates = Collections.singletonList(certificate);
        this.key = key;
    }

    @Override
    public List<X509Certificate> getSigningCertificateChain()
    {
        return this.certificates;
    }

    @Override
    public PrivateKey getSigningKey(X509Certificate signingCert)
    {
        return this.key;
    }
}
