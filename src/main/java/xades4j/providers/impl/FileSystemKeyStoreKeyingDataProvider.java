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
import java.security.Provider;
import java.security.cert.X509Certificate;

/**
 * A specification of {@link KeyStoreKeyingDataProvider} for file-system keystores.
 * The protection parameter to access the entry is a {@link KeyStore.PasswordProtection}
 * with a password obtained directly from the {@link KeyStorePasswordProvider}.
 * <p>
 * The {@link FileSystemKeyStoreKeyingDataProvider#builder(String, String, SigningCertificateSelector)}  builder} method
 * can be used to configure and create a new instance.
 *
 * @author Luís
 * @see xades4j.providers.impl.KeyStoreKeyingDataProvider
 */
public final class FileSystemKeyStoreKeyingDataProvider extends KeyStoreKeyingDataProvider
{
    /**
     * Create a builder to configure a new {@link FileSystemKeyStoreKeyingDataProvider}.
     *
     * @param keyStoreType        the type of the keystore (jks, pkcs12, etc)
     * @param keyStorePath        the file-system path of the keystore
     * @param certificateSelector the selector of signing certificate
     * @return the builder
     */
    public static Builder builder(String keyStoreType, String keyStorePath, SigningCertificateSelector certificateSelector)
    {
        return new Builder(keyStoreType, keyStorePath, certificateSelector);
    }

    private FileSystemKeyStoreKeyingDataProvider(Builder builder)
    {
        super(loadProtection -> KeyStore.Builder.newInstance(
                builder.keyStoreType,
                builder.provider,
                new File(builder.keyStorePath),
                loadProtection),
                builder.certificateSelector,
                builder.storePasswordProvider,
                builder.entryPasswordProvider,
                builder.fullChain);
    }

    @Override
    protected KeyStore.ProtectionParameter getKeyProtection(
            String entryAlias,
            X509Certificate entryCert,
            KeyEntryPasswordProvider entryPasswordProvider)
    {
        if (null == entryPasswordProvider)
        {
            return null;
        }

        return new KeyStore.PasswordProtection(entryPasswordProvider.getPassword(entryAlias, entryCert));
    }

    public static final class Builder
    {
        private final String keyStoreType;
        private final String keyStorePath;
        private final SigningCertificateSelector certificateSelector;
        private KeyStorePasswordProvider storePasswordProvider;
        private KeyEntryPasswordProvider entryPasswordProvider;
        private boolean fullChain;
        private Provider provider;

        private Builder(String keyStoreType, String keyStorePath, SigningCertificateSelector certificateSelector)
        {
            this.keyStoreType = keyStoreType;
            this.keyStorePath = keyStorePath;
            this.certificateSelector = certificateSelector;
            this.fullChain = false;
        }

        /**
         * Create a new {@link PKCS11KeyStoreKeyingDataProvider} based on the current configuration.
         *
         * @return the provider
         */
        public FileSystemKeyStoreKeyingDataProvider build()
        {
            return new FileSystemKeyStoreKeyingDataProvider(this);
        }

        /**
         * Sets the provider of the keystore loading password.
         *
         * @param storePasswordProvider keystore password provider
         * @return the current instance
         */
        public Builder storePassword(KeyStorePasswordProvider storePasswordProvider)
        {
            this.storePasswordProvider = storePasswordProvider;
            return this;
        }

        /**
         * Sets the provider of entry passwords
         *
         * @param entryPasswordProvider entry password provider
         * @return the current instance
         */
        public Builder entryPassword(KeyEntryPasswordProvider entryPasswordProvider)
        {
            this.entryPasswordProvider = entryPasswordProvider;
            return this;
        }

        /**
         * Sets whether the full certificate chain should be returned, if available.
         *
         * @param fullChain {@code true} to return the full certificate chain, false otherwise
         * @return the current instance
         */
        public Builder fullChain(boolean fullChain)
        {
            this.fullChain = fullChain;
            return this;
        }

        /**
         * Sets the provider from which the KeyStore is to be instantiated.
         *
         * @param provider the provider
         * @return the current instance
         */
        public Builder provider(Provider provider)
        {
            this.provider = provider;
            return this;
        }
    }
}
