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
package xades4j.providers.impl;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.SigningKeyException;
import xades4j.verification.UnexpectedJCAException;

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
    public List<X509Certificate> getSigningCertificateChain() throws SigningCertChainException, UnexpectedJCAException
    {
        return this.certificates;
    }

    @Override
    public PrivateKey getSigningKey(X509Certificate signingCert) throws SigningKeyException, UnexpectedJCAException
    {
        return this.key;
    }
}
