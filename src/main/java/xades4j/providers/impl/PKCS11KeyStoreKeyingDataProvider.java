/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.providers.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * A specification of {@code KeyStoreKeyingDataProvider} for PKCS#11 keystores.
 * This class uses the SUN's PKCS#11 provider, which brigdes with the native PKCS#11
 * library.
 * <p>
 * The {@code KeyStorePasswordProvider} and {@code KeyEntryPasswordProvider} may
 * be {@code null}. In that case the keystore protection has to be handled by the
 * native library. If the {@code KeyEntryPasswordProvider} is supplied, the protection
 * used to access an entry is a {@code CallbackHandlerProtection} that invokes the
 * {@code KeyEntryPasswordProvider} exactly when when the password is requested.
 * @author Luís
 */
public class PKCS11KeyStoreKeyingDataProvider extends KeyStoreKeyingDataProvider
{
    /**
     *
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
        super(new KeyStoreBuilderCreator()
        {
            @Override
            public Builder getBuilder(ProtectionParameter loadProtection)
            {
                StringBuilder config = new StringBuilder("name = ").append(providerName);
                config.append(System.getProperty("line.separator"));
                config.append("library = ").append(nativeLibraryPath);
                ByteArrayInputStream configStream = new ByteArrayInputStream(config.toString().getBytes());

                Provider p = new sun.security.pkcs11.SunPKCS11(configStream);
                Security.addProvider(p);

                return KeyStore.Builder.newInstance(
                        "PKCS11",
                        p,
                        loadProtection);
            }
        }, certificateSelector, keyStorePasswordProvider, entryPasswordProvider, returnFullChain);
    }

    @Override
    protected final KeyStore.ProtectionParameter getKeyProtection(
            final String entryAlias,
            final X509Certificate entryCert,
            final KeyEntryPasswordProvider entryPasswordProvider)
    {
        if (null == entryPasswordProvider)
            return null;

        return new KeyStore.CallbackHandlerProtection(new CallbackHandler()
        {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException
            {
                PasswordCallback c = (PasswordCallback)callbacks[0];
                c.setPassword(entryPasswordProvider.getPassword(entryAlias, entryCert));
            }
        });
    }
}
