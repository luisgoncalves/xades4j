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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
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
 * A specification of {@code KeyStoreKeyingDataProvider} for PKCS#11 keystores.
 * This class uses the SUN's PKCS#11 provider, which brigdes with the native PKCS#11
 * library. Note that this provider is not included in some versions of the JRE,
 * namely the 64 bits Windows version. On those scenarios this class will fail at
 * runtime.
 * <p>
 * The {@code KeyStorePasswordProvider} and {@code KeyEntryPasswordProvider} may
 * be {@code null}. In that case the keystore protection has to be handled by the
 * native library. If the {@code KeyEntryPasswordProvider} is supplied, the protection
 * used to access an entry is a {@code CallbackHandlerProtection} that invokes the
 * {@code KeyEntryPasswordProvider} exactly when when the password is requested.
 * @see xades4j.providers.impl.KeyStoreKeyingDataProvider
 * @author Luís
 */
public class PKCS11KeyStoreKeyingDataProvider extends KeyStoreKeyingDataProvider
{
    /**
     * The provider name is used has a key to search for installed providers. If a
     * provider exists with the same name, it will be used even if it relies on a
     * different native library.
     * @param nativeLibraryPath the path for the native library of the specific PKCS#11 provider
     * @param providerName this string is concatenated with the prefix SunPKCS11- to produce this provider instance's name
     * @param certificateSelector the selector of signing certificate
     * @param keyStorePasswordProvider the provider of the keystore loading password (may be {@code null})
     * @param entryPasswordProvider the provider of entry passwords (may be {@code null})
     * @param returnFullChain indicates of the full certificate chain should be returned, if available
     * @throws KeyStoreException
     */
    public PKCS11KeyStoreKeyingDataProvider(
            final String nativeLibraryPath,
            final String providerName,
            SigningCertSelector certificateSelector,
            KeyStorePasswordProvider keyStorePasswordProvider,
            KeyEntryPasswordProvider entryPasswordProvider,
            boolean returnFullChain) throws KeyStoreException
    {
        this(nativeLibraryPath, providerName, null,
             certificateSelector, keyStorePasswordProvider, entryPasswordProvider,
             returnFullChain);
    }

    /**
     * The provider name is used as a key to search for installed providers. If a
     * provider exists with the same name, it will be used even if it relies on a
     * different native library.
     * @param nativeLibraryPath the path for the native library of the specific PKCS#11 provider
     * @param providerName this string is concatenated with the prefix SunPKCS11- to produce this provider instance's name
     * @param slotId the id of the slot that this provider instance is to be associated with (can be {@code null})
     * @param certificateSelector the selector of signing certificate
     * @param keyStorePasswordProvider the provider of the keystore loading password (can be {@code null})
     * @param entryPasswordProvider the provider of entry passwords (may be {@code null})
     * @param returnFullChain indicates of the full certificate chain should be returned, if available
     * @throws KeyStoreException
     */
    public PKCS11KeyStoreKeyingDataProvider(
            final String nativeLibraryPath,
            final String providerName,
            final Integer slotId,
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
                Provider p = getInstalledProvider(providerName);
                if (p == null)
                {
                    StringBuilder config = new StringBuilder("name = ").append(providerName);
                    config.append(System.getProperty("line.separator"));
                    config.append("library = ").append(nativeLibraryPath);
                    if(slotId != null)
                    {
                        config.append(System.getProperty("line.separator"));
                        config.append("slot = ").append(slotId);
                    }
                    ByteArrayInputStream configStream = new ByteArrayInputStream(config.toString().getBytes());
                    p = createPkcs11Provider(configStream);
                    Security.addProvider(p);
                }

                return KeyStore.Builder.newInstance("PKCS11", p, loadProtection);
            }
        }, certificateSelector, keyStorePasswordProvider, entryPasswordProvider, returnFullChain);
    }

    /**
     * Shortcut constructor using {@code null} for the password providers and slot
     * and {@code false} for the {@code returnFullChain} parameter.
     * @param nativeLibraryPath
     * @param providerName
     * @param slotId
     * @param certificateSelector
     * @throws KeyStoreException
     */
    public PKCS11KeyStoreKeyingDataProvider(
            String nativeLibraryPath,
            String providerName,
            Integer slotId,
            SigningCertSelector certificateSelector) throws KeyStoreException
    {
        this(nativeLibraryPath, providerName, slotId, certificateSelector, null, null, false);
    }

    /**
     * Shortcut constructor using {@code null} for the password providers and slot,
     * and {@code false} for the {@code returnFullChain} parameter.
     * @param nativeLibraryPath
     * @param providerName
     * @param certificateSelector
     * @throws KeyStoreException
     */
    public PKCS11KeyStoreKeyingDataProvider(
            final String nativeLibraryPath,
            final String providerName,
            SigningCertSelector certificateSelector) throws KeyStoreException
    {
        this(nativeLibraryPath, providerName, null, certificateSelector);
    }

    @Override
    protected final KeyStore.ProtectionParameter getKeyProtection(
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

    private static Provider getInstalledProvider(String providerName)
    {
        Class<Provider> pkcs11Class = getPkcs11ProviderClass();
        Provider p = Security.getProvider("SunPKCS11-" + providerName);
        // Throws expcetion if the provider is not of the expected type
        return pkcs11Class.cast(p);
    }

    private static Provider createPkcs11Provider(InputStream configStream)
    {
        try
        {
            Class<Provider> providerClass = getPkcs11ProviderClass();
            Constructor<Provider> ctor = providerClass.getConstructor(InputStream.class);
            return ctor.newInstance(configStream);
        }
        // Since the provider class was loaded, these exceptions are unexpected
        catch (IllegalAccessException ex)
        {
            throw new ProviderException(ex);
        }
        catch (IllegalArgumentException ex)
        {
            throw new ProviderException(ex);
        }
        catch (InvocationTargetException ex)
        {
            throw new ProviderException(ex);
        }
        catch (NoSuchMethodException ex)
        {
            throw new ProviderException(ex);
        }
        catch(InstantiationException ex)
        {
            throw new ProviderException(ex);
        }
    }

    private static Class getPkcs11ProviderClass()
    {
        try
        {
            return Class.forName("sun.security.pkcs11.SunPKCS11");
        }
        catch (ClassNotFoundException ex)
        {
           throw new ProviderException("Cannot find SunPKCS11 provider", ex);
        }
    }
    
    public static boolean isProviderAvailable()
    {
        try
        {
            getPkcs11ProviderClass();
            return true;
        }
        catch(ProviderException ex)
        {
            return false;
        }
    }
}
