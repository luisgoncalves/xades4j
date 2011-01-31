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

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import xades4j.utils.SignatureServicesTestBase;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class FileSystemKeyStoreKeyingDataProviderTest
{
    FileSystemKeyStoreKeyingDataProvider keyingProvider;
    X509Certificate signCert;

    @Before
    public void setUp() throws Exception
    {
        keyingProvider = new FileSystemKeyStoreKeyingDataProvider(
                "pkcs12",
                SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.pfx"),
                new FirstCertificateSelector(),
                new DirectPasswordProvider("mykeypass"),
                new DirectPasswordProvider("mykeypass"), true);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        signCert = (X509Certificate)cf.generateCertificate(
                new FileInputStream(SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.cer")));
    }

    @Test
    public void testGetSigningKey() throws Exception
    {
        keyingProvider.getSigningKey(signCert);
    }

    @Test
    public void testGetSigningCertificateChain() throws Exception
    {
        List<X509Certificate> certChain = keyingProvider.getSigningCertificateChain();
        assertEquals(certChain.size(), 3);
        assertEquals(certChain.get(0), signCert);
    }
}
