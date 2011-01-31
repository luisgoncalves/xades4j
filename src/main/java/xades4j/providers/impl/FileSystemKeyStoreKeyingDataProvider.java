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

import java.io.File;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

/**
 * A specification of {@code KeyStoreKeyingDataProvider} for file-system keystores.
 * The protection parameter to access the entry is a {@code PasswordProtection}
 * with a password obtained directly from the {@code KeyStorePasswordProvider}.
 * @see xades4j.providers.impl.KeyStoreKeyingDataProvider
 * @author Luís
 */
public class FileSystemKeyStoreKeyingDataProvider extends KeyStoreKeyingDataProvider
{
    /**
     * @param keyStoreType the type of the keystore (jks, pkcs12, etc)
     * @param keyStorePath the file-system path of the keystore
     * @param certificateSelector the selector of signing certificate
     * @param keyStorePasswordProvider the provider of the keystore loading password
     * @param entryPasswordProvider the provider of entry passwords
     * @param returnFullChain indicates of the full certificate chain should be returned, if available
     * @throws KeyStoreException
     */
    public FileSystemKeyStoreKeyingDataProvider(
            final String keyStoreType,
            final String keyStorePath,
            SigningCertSelector certificateSelector,
            KeyStorePasswordProvider keyStorePasswordProvider,
            KeyEntryPasswordProvider entryPasswordProvider,
            boolean returnFullChain) throws KeyStoreException
    {
        super(new KeyStoreBuilderCreator()
        {
            @Override
            public Builder getBuilder(ProtectionParameter loadProtection)
            {
                return KeyStore.Builder.newInstance(
                        keyStoreType,
                        null,
                        new File(keyStorePath),
                        loadProtection);
            }
        },
                certificateSelector,
                keyStorePasswordProvider,
                entryPasswordProvider,
                returnFullChain);
    }

    @Override
    protected KeyStore.ProtectionParameter getKeyProtection(
            String entryAlias,
            X509Certificate entryCert,
            KeyEntryPasswordProvider entryPasswordProvider)
    {
        return new KeyStore.PasswordProtection(entryPasswordProvider.getPassword(entryAlias, entryCert));
    }
}
