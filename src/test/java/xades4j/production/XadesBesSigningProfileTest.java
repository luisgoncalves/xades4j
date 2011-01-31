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
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.SigningKeyException;
import xades4j.verification.UnexpectedJCAException;

/**
 *
 * @author Luís
 */
public class XadesBesSigningProfileTest
{
    public XadesBesSigningProfileTest()
    {
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Before
    public void setUp()
    {
    }

    @After
    public void tearDown()
    {
    }

    @Test
    public void testGetSigner() throws XadesProfileResolutionException
    {
        XadesSigner s = new XadesBesSigningProfile(new KeyingDataProvider()
        {
            @Override
            public List<X509Certificate> getSigningCertificateChain() throws SigningCertChainException, UnexpectedJCAException
            {
                throw new UnsupportedOperationException();
            }

            @Override
            public PrivateKey getSigningKey(X509Certificate signingCert) throws SigningKeyException, UnexpectedJCAException
            {
                throw new UnsupportedOperationException();
            }
        }).newSigner();

        assertNotNull(s);
    }
}
