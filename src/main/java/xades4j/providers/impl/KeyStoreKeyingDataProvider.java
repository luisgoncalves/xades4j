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

import xades4j.providers.*;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import xades4j.verification.UnexpectedJCAException;

/**
 * A KeyStore-based implementation of {@code KeyingDataProvider}. The keystore is
 * loaded on first access (thread-safe).
 * <p>
 * The following procedure is done to get the signing certificate:
 * <ol>
 *  <li>Get all the X509Certificates in private key entries</li>
 *  <li>Invoke the supplied {@code SigningCertSelector} to choose the certificate and thus the entry</li>
 *  <li>Get the entry alias matching the selected certificate</li>
 *  <li>Get the certificate chain for that entry</li>
 * </ol>
 * <p>
 * The following procedure is done to get the signing key:
 * <ol>
 *  <li>Get the entry alias matching the provided certificate</li>
 *  <li>Get the protection to access that entry</li>
 *  <li>Return the entry's private key</li>
 * </ol>
 *
 * @see FileSystemKeyStoreKeyingDataProvider
 * @see PKCS11KeyStoreKeyingDataProvider
 * @author Luís
 */
public abstract class KeyStoreKeyingDataProvider implements KeyingDataProvider
{
    /**
     * Provides a password to load the keystore.
     */
    public interface KeyStorePasswordProvider
    {
        char[] getPassword();
    }

    /**
     * Provides a password to access a keystore entry. Must be thread-safe.
     */
    public interface KeyEntryPasswordProvider
    {
        char[] getPassword(String entryAlias, X509Certificate entryCert);
    }

    /**
     * Used to select a certificate from the available certificates. All the
     * X509Certificates in private key entries are passed.
     */
    public interface SigningCertSelector
    {
        X509Certificate selectCertificate(
                List<X509Certificate> availableCertificates);
    }
    /**/

    /**
     * Gets a builder that will create the keystore instance. This is usued because
     * different types of keystores may be configured differently.
     */
    protected interface KeyStoreBuilderCreator
    {
        /**
         * @param loadProtection the protection that should be used to load the keystore (may be null)
         * @return the builder
         */
        Builder getBuilder(ProtectionParameter loadProtection);
    }
    /**/
    /**/
    
    private final KeyStoreBuilderCreator builderCreator;
    private final SigningCertSelector certificateSelector;
    private final KeyStorePasswordProvider storePasswordProvider;
    private final KeyEntryPasswordProvider entryPasswordProvider;
    private final boolean returnFullChain;

    private KeyStore keyStore;
    private final Object lockObj;
    private boolean initialized;

    /**
     *
     * @param builderCreator
     * @param certificateSelector
     * @param storePasswordProvider
     * @param entryPasswordProvider
     * @param returnFullChain return the full certificate chain, if available
     */
    protected KeyStoreKeyingDataProvider(
            KeyStoreBuilderCreator builderCreator,
            SigningCertSelector certificateSelector,
            KeyStorePasswordProvider storePasswordProvider,
            KeyEntryPasswordProvider entryPasswordProvider,
            boolean returnFullChain)
    {
        this.builderCreator = builderCreator;
        this.certificateSelector = certificateSelector;
        this.storePasswordProvider = storePasswordProvider;
        this.entryPasswordProvider = entryPasswordProvider;
        this.returnFullChain = returnFullChain;

        this.lockObj = new Object();
        this.initialized = false;
    }

    private void ensureInitialized() throws UnexpectedJCAException
    {
        synchronized(this.lockObj)
        {
            if (!this.initialized)
            {
                try
                {
                    KeyStore.CallbackHandlerProtection storeLoadProtec = null;
                    if (storePasswordProvider != null)
                        // Create the load protection with callback.
                        storeLoadProtec = new KeyStore.CallbackHandlerProtection(new CallbackHandler()
                        {
                            @Override
                            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException
                            {
                                PasswordCallback c = (PasswordCallback)callbacks[0];
                                c.setPassword(storePasswordProvider.getPassword());
                            }
                        });
                    else
                        // If no load password provider is supplied is because it shouldn't
                        // be needed. Create a dummy protection because the keystore
                        // builder needs it to be non-null.
                        storeLoadProtec = new KeyStore.CallbackHandlerProtection(new CallbackHandler()
                        {
                            @Override
                            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException
                            {
                                throw new UnsupportedOperationException("No KeyStorePasswordProvider");
                            }
                        });
                    this.keyStore = builderCreator.getBuilder(storeLoadProtec).getKeyStore();
                }
                catch (KeyStoreException ex)
                {
                    throw new UnexpectedJCAException("The keystore couldn't be initialized", ex);
                }
                this.initialized = true;
            }
        }
    }

    @Override
    public List<X509Certificate> getSigningCertificateChain() throws SigningCertChainException, UnexpectedJCAException
    {
        ensureInitialized();
        try
        {
            List<X509Certificate> availableSignCerts = new ArrayList<X509Certificate>(keyStore.size());

            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();)
            {
                String alias = aliases.nextElement();
                if (keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class))
                {
                    Certificate cer = keyStore.getCertificate(alias);
                    if (cer instanceof X509Certificate)
                        availableSignCerts.add((X509Certificate)cer);
                }
            }

            if (availableSignCerts.isEmpty())
                throw new SigningCertChainException("No certificates available in the key store");

            // Select the signing certificate from the available certificates.
            X509Certificate signingCert = this.certificateSelector.selectCertificate(availableSignCerts);

            String signingCertAlias = this.keyStore.getCertificateAlias(signingCert);
            if (null == signingCertAlias)
                throw new SigningCertChainException("Selected certificate not present in the key store");

            Certificate[] signingCertChain = this.keyStore.getCertificateChain(signingCertAlias);
            if (null == signingCertChain)
                throw new SigningCertChainException("Selected certificate doesn't match a key and corresponding certificate chain");

            if (this.returnFullChain)
            {
                List lChain = Arrays.asList(signingCertChain);
                return Collections.checkedList(lChain, X509Certificate.class);
            } else
                return Collections.singletonList((X509Certificate)signingCertChain[0]);

        } catch (KeyStoreException ex)
        {
            // keyStore.getCertificateAlias, keyStore.getCertificateChain -> if the
            // keystore is not loaded.
            throw new UnexpectedJCAException(ex.getMessage(), ex);
        }
    }

    @Override
    public PrivateKey getSigningKey(X509Certificate signingCert) throws SigningKeyException, UnexpectedJCAException
    {
        ensureInitialized();
        try
        {
            // The certificate supplied by the library is always the first certificate
            // in the chain supplied by getSigningCertificateChain, which means
            // that an entry will always be present. Also, this entry is always
            // a PrivateKeyEntry.
            String entryAlias = this.keyStore.getCertificateAlias(signingCert);
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)this.keyStore.getEntry(
                    entryAlias,
                    getKeyProtection(entryAlias, signingCert, this.entryPasswordProvider));
            return entry.getPrivateKey();
        }
        catch (UnrecoverableKeyException ex)
        {
            throw new SigningKeyException("Invalid key entry password", ex);
        }
        catch (GeneralSecurityException ex)
        {
            // NoSuchAlgorithmException
            // UnrecoverableEntryException
            // KeyStoreException
            throw new UnexpectedJCAException(ex.getMessage(), ex);
        }
    }

    /**
     * Gets a protection parameter to access the specified entry.
     * @param entryAlias the alias of the entry that is being accessed
     * @param entryCert the cerificate in the entry
     * @param entryPasswordProvider the password provider that should be used to
     *      get the actual password (may be {@code null})
     * @return the protection
     */
    protected abstract KeyStore.ProtectionParameter getKeyProtection(
            String entryAlias,
            X509Certificate entryCert,
            KeyEntryPasswordProvider entryPasswordProvider);
}
