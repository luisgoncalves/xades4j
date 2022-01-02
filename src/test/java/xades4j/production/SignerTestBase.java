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

import java.io.File;
import java.security.KeyStoreException;

import static org.junit.Assume.assumeTrue;

import org.w3c.dom.Document;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.utils.SignatureServicesTestBase;

/**
 * @author Luís
 */
public class SignerTestBase extends SignatureServicesTestBase
{
    /**/
    static protected KeyingDataProvider keyingProviderMy;
    static protected KeyingDataProvider keyingProviderMyEc;
    static protected KeyingDataProvider keyingProviderNist;

    static protected String PTCC_PKCS11_LIB_PATH;

    static
    {
        try
        {
            keyingProviderMy = createFileSystemKeyingDataProvider("JKS", "my/LG.jks", "mykeypass", true);
            keyingProviderMyEc = createFileSystemKeyingDataProvider("PKCS12", "my/lg_ec.p12", "mykeypass", true);
            keyingProviderNist = createFileSystemKeyingDataProvider("JKS", "csrc.nist/test4.jks", "password", false);
        }
        catch (KeyStoreException e)
        {
            throw new IllegalStateException("SignerTestBase init failed: " + e.getMessage());
        }

        PTCC_PKCS11_LIB_PATH = onMacOs()
                ? "/usr/local/lib/libpteidpkcs11.dylib"
                : onWindows()
                ? "C:\\Windows\\System32\\pteidpkcs11.dll"
                : "<unavailable>";
    }

    public static Document getTestDocument() throws Exception
    {
        return getDocument("document.xml");
    }

    protected static FileSystemKeyStoreKeyingDataProvider createFileSystemKeyingDataProvider(
            String keyStoreType,
            String keyStorePath,
            String keyStorePwd,
            boolean returnFullChain) throws KeyStoreException
    {
        keyStorePath = toPlatformSpecificCertDirFilePath(keyStorePath);
        return new FileSystemKeyStoreKeyingDataProvider(keyStoreType, keyStorePath,
                KeyStoreKeyingDataProvider.SigningCertificateSelector.single(),
                new DirectPasswordProvider(keyStorePwd),
                new DirectPasswordProvider(keyStorePwd), returnFullChain);
    }

    /**
     * Skips tests that are executing when the PT citizen card PKCS11 library is not available.
     */
    protected static void assumePtCcPkcs11()
    {
        assumeTrue(PKCS11KeyStoreKeyingDataProvider.isProviderAvailable());
        assumeTrue(new File(PTCC_PKCS11_LIB_PATH).exists());
    }

    protected static void assumeWindows()
    {
        assumeTrue(onWindows());
    }
}
