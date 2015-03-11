package xades4j.providers.impl;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class PlainObjectsKeyStoreKeyingDataProvider extends KeyStoreKeyingDataProvider
{
    /**
     * @param certificateSelector
     * @param storePasswordProvider
     * @param entryPasswordProvider
     * @param returnFullChain       return the full certificate chain, if available
     */
    public PlainObjectsKeyStoreKeyingDataProvider(
            final PrivateKey privateKey,
            final X509Certificate[] certificateChain,
            final String alias,
            SigningCertSelector certificateSelector,
            KeyStorePasswordProvider storePasswordProvider,
            KeyEntryPasswordProvider entryPasswordProvider,
            boolean returnFullChain)
    {
        super(new KeyStoreBuilderCreator()
        {
            @Override
            public KeyStore.Builder getBuilder(KeyStore.ProtectionParameter loadProtection)
            {
                try
                {
                    KeyStore ks = KeyStore.getInstance("JKS", "SUN");
                    ks.load(null, null);
                    ks.setKeyEntry(alias, privateKey, null, certificateChain);
                    return KeyStore.Builder.newInstance(ks, new KeyStore.PasswordProtection(null));
                }
                catch (KeyStoreException | NoSuchProviderException | CertificateException | IOException | NoSuchAlgorithmException e)
                {
                    throw new RuntimeException(e.getMessage());
                }
            }
        }, certificateSelector, storePasswordProvider, entryPasswordProvider, returnFullChain);
    }

    @Override
    protected KeyStore.ProtectionParameter getKeyProtection(
            String entryAlias,
            X509Certificate entryCert,
            KeyEntryPasswordProvider entryPasswordProvider)
    {
        return null;
    }
}
