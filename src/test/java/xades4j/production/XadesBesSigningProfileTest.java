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
package xades4j.production;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.providers.KeyingDataProvider;

/**
 *
 * @author Luís
 */
public class XadesBesSigningProfileTest
{
    @Test
    public void testGetSigner() throws XadesProfileResolutionException
    {
        XadesSigner s = new XadesBesSigningProfile(new KeyingDataProvider()
        {
            @Override
            public List<X509Certificate> getSigningCertificateChain()
            {
                throw new UnsupportedOperationException();
            }

            @Override
            public PrivateKey getSigningKey(X509Certificate signingCert)
            {
                throw new UnsupportedOperationException();
            }
        }).newSigner();

        assertNotNull(s);
    }
}
