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
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import xades4j.utils.SignatureServicesTestBase;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
@RunWith(Parameterized.class)
public class FileSystemKeyStoreKeyingDataProviderTest
{
    @Parameterized.Parameter(0)
    public FileSystemKeyStoreKeyingDataProvider keyingProvider;
    @Parameterized.Parameter(1)
    public X509Certificate signCert;

    @Parameterized.Parameters
    public static Collection<Object[]> data() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        FileSystemKeyStoreKeyingDataProvider  keyingProviderPksc12 = new FileSystemKeyStoreKeyingDataProvider(
                "pkcs12",
                SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.pfx"),
                new FirstCertificateSelector(),
                new DirectPasswordProvider("mykeypass"),
                new DirectPasswordProvider("mykeypass"), true);
        FileSystemKeyStoreKeyingDataProvider  keyingProviderJks = new FileSystemKeyStoreKeyingDataProvider(
                "JKS",
                SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.jks"),
                new FirstCertificateSelector(),
                new DirectPasswordProvider("mykeypass"),
                new DirectPasswordProvider("mykeypass"), true);
        FileSystemKeyStoreKeyingDataProvider  keyingProviderPksc12BC = new FileSystemKeyStoreKeyingDataProvider(
                "pkcs12",
                SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.pfx"),
                new FirstCertificateSelector(),
                new DirectPasswordProvider("mykeypass"),
                new DirectPasswordProvider("mykeypass"), true,new BouncyCastleProvider());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate signCert = (X509Certificate)cf.generateCertificate(
                new FileInputStream(SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.cer")));
        ArrayList<Object[]> result = new ArrayList<Object[]>();
        result.add(new Object[]{keyingProviderPksc12,signCert});

        //TODO test will break, need find out why
        //result.add(new Object[]{keyingProviderPksc12BC,signCert});
        result.add(new Object[]{keyingProviderJks,signCert});
        return result;
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
