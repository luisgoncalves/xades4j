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

import xades4j.utils.FileUtils;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * A specification of {@link KeyStoreKeyingDataProvider} for PKCS#11 keystores.
 * This class uses the SUN's PKCS#11 provider, which brigdes with a native PKCS#11
 * library. Note that this provider may not be included in some versions of the JRE,
 * On those scenarios this class will fail at runtime.
 * <p>
 * The {@link PKCS11KeyStoreKeyingDataProvider#builder(String, SigningCertificateSelector) builder} method can be used
 * to configure and create a new instance. If a name for the underlying PKCS#11 provider is not specified, a default
 * value is used which is based on the native library path. Duplicate names will cause an exception.
 * <p>
 * The {@link KeyStorePasswordProvider} and {@link KeyEntryPasswordProvider} may be {@code null}, in which case the
 * keystore protection has to be handled by the native library. If the {@link KeyEntryPasswordProvider} is supplied,
 * the protection used to access an entry is a {@link KeyStore.CallbackHandlerProtection} that invokes the
 * {@link KeyEntryPasswordProvider} exactly when when the password is requested.
 *
 * @author Luís
 * @see xades4j.providers.impl.KeyStoreKeyingDataProvider
 */
public final class PKCS11KeyStoreKeyingDataProvider extends KeyStoreKeyingDataProvider
{
    private static String SUN_PKCS11_PROVIDER = "SunPKCS11";

    /**
     * Create a builder to configure a new {@link PKCS11KeyStoreKeyingDataProvider}.
     *
     * @param nativeLibraryPath   path for the native library of the specific PKCS#11 provider
     * @param certificateSelector selector of the signing certificate
     * @return the builder
     */
    public static Builder builder(String nativeLibraryPath, SigningCertificateSelector certificateSelector)
    {
        return new Builder(nativeLibraryPath, certificateSelector);
    }

    private PKCS11KeyStoreKeyingDataProvider(Builder builder)
    {
        super(new KeyStoreBuilderCreator()
        {
            @Override
            public KeyStore.Builder getBuilder(ProtectionParameter loadProtection)
            {
                Provider provider = createProvider(serializeConfiguration(builder.providerName, builder.nativeLibraryPath, builder.slotId));
                if (Security.addProvider(provider) == -1)
                {
                    throw new ProviderException("PKCS11 provider already installed");
                }
                return KeyStore.Builder.newInstance("PKCS11", provider, loadProtection);
            }
        }, builder.certificateSelector, builder.storePasswordProvider, builder.entryPasswordProvider, builder.fullChain);
    }

    private static String serializeConfiguration(String name, String nativeLibraryPath, Integer slotId)
    {
        String newLine = System.getProperty("line.separator");
        StringBuilder config = new StringBuilder()
                .append("name = ").append(name).append(newLine)
                .append("library = ").append(nativeLibraryPath).append(newLine);
        if (slotId != null)
        {
            config.append("slot = ").append(slotId).append(newLine);
        }
        return config.toString();
    }

    private static Provider createProvider(String configuration)
    {
        try
        {
            Provider provider = Security.getProvider(SUN_PKCS11_PROVIDER);
            if (provider == null)
            {
                throw new ProviderException("PKCS11 provider not available");
            }
            return provider.configure(FileUtils.writeTempFile(configuration));
        }
        catch (IOException e)
        {
            throw new ProviderException("Cannot configure PKCS11 provider", e);
        }
    }

    @Override
    protected KeyStore.ProtectionParameter getKeyProtection(
            final String entryAlias,
            final X509Certificate entryCert,
            final KeyEntryPasswordProvider entryPasswordProvider)
    {
        if (null == entryPasswordProvider)
        {
            return null;
        }

        return new KeyStore.CallbackHandlerProtection(new CallbackHandler()
        {

            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException
            {
                PasswordCallback c = (PasswordCallback) callbacks[0];
                c.setPassword(entryPasswordProvider.getPassword(entryAlias, entryCert));
            }
        });
    }

    public static final class Builder
    {
        private final String nativeLibraryPath;
        private final SigningCertificateSelector certificateSelector;
        private String providerName;
        private boolean fullChain;
        private Integer slotId;
        private KeyStorePasswordProvider storePasswordProvider;
        private KeyEntryPasswordProvider entryPasswordProvider;

        private Builder(String nativeLibraryPath, SigningCertificateSelector certificateSelector)
        {
            this.nativeLibraryPath = nativeLibraryPath;
            this.certificateSelector = certificateSelector;
            this.providerName = "xades4j-" + nativeLibraryPath;
            this.fullChain = false;
        }

        /**
         * Create a new {@link PKCS11KeyStoreKeyingDataProvider} based on the current configuration.
         *
         * @return the provider
         */
        public PKCS11KeyStoreKeyingDataProvider build()
        {
            return new PKCS11KeyStoreKeyingDataProvider(this);
        }

        /**
         * Sets the underlying PKCS#11 provider name. If the name is already in use, an exception is thrown.
         *
         * @param providerName the provider name
         * @return the current instance
         */
        public Builder providerName(String providerName)
        {
            this.providerName = providerName;
            return this;
        }

        /**
         * Sets the id of the slot that this provider instance is to be associated with.
         *
         * @param slotId the slot ID
         * @return the current instance
         */
        public Builder slot(int slotId)
        {
            this.slotId = slotId;
            return this;
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
    }

    public static boolean isProviderAvailable()
    {
        return Security.getProvider(SUN_PKCS11_PROVIDER) != null;
    }
}
