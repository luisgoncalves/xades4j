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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import xades4j.utils.SignatureServicesTestBase;

/**
 * @author Luís
 */
public class FileSystemKeyStoreKeyingDataProviderTest
{
    @BeforeAll
    public static void setup()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterAll
    public static void cleanup()
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    public static Collection<Arguments> data() throws Exception
    {
        FileSystemKeyStoreKeyingDataProvider keyingProviderPkcs12 = FileSystemKeyStoreKeyingDataProvider
                .builder("pkcs12",
                        SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.pfx"),
                        KeyStoreKeyingDataProvider.SigningCertificateSelector.single())
                .storePassword(new DirectPasswordProvider("mykeypass"))
                .entryPassword(new DirectPasswordProvider("mykeypass"))
                .fullChain(true)
                .build();
        FileSystemKeyStoreKeyingDataProvider keyingProviderJks = FileSystemKeyStoreKeyingDataProvider
                .builder("JKS",
                        SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.jks"),
                        KeyStoreKeyingDataProvider.SigningCertificateSelector.single())
                .storePassword(new DirectPasswordProvider("mykeypass"))
                .entryPassword(new DirectPasswordProvider("mykeypass"))
                .fullChain(true)
                .build();
        FileSystemKeyStoreKeyingDataProvider keyingProviderPkcs12BC = FileSystemKeyStoreKeyingDataProvider
                .builder("pkcs12",
                        SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.pfx"),
                        KeyStoreKeyingDataProvider.SigningCertificateSelector.single())
                .storePassword(new DirectPasswordProvider("mykeypass"))
                .entryPassword(new DirectPasswordProvider("mykeypass"))
                .fullChain(true)
                .provider(new BouncyCastleProvider())
                .build();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate signCert = (X509Certificate) cf.generateCertificate(
                new FileInputStream(SignatureServicesTestBase.toPlatformSpecificCertDirFilePath("my/LG.cer")));

        return List.of(
                arguments(keyingProviderPkcs12, signCert),
                //TODO test will break, need find out why
                //arguments(keyingProviderPkcs12BC, signCert),
                arguments(keyingProviderJks, signCert)
        );
    }

    @ParameterizedTest
    @MethodSource("data")
    void testGetSigningKey(FileSystemKeyStoreKeyingDataProvider keyingProvider, X509Certificate signCert) throws Exception
    {
        keyingProvider.getSigningKey(signCert);
    }

    @ParameterizedTest
    @MethodSource("data")
    void testGetSigningCertificateChain(FileSystemKeyStoreKeyingDataProvider keyingProvider, X509Certificate signCert) throws Exception
    {
        List<X509Certificate> certChain = keyingProvider.getSigningCertificateChain();
        assertEquals(3, certChain.size());
        assertEquals(certChain.get(0), signCert);
    }
}
