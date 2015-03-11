package xades4j.providers.impl;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class PlainObjectsKeyStoreKeyingDataProvider extends KeyStoreKeyingDataProvider
{
    private static final String PASSWORD = "anything";

    /**
     * @param certificateSelector
     * @param storePasswordProvider
     * @param entryPasswordProvider
     * @param returnFullChain       return the full certificate chain, if available
     */
    public PlainObjectsKeyStoreKeyingDataProvider(
            final String alias,
            final PrivateKey privateKey,
            final X509Certificate[] certificateChain,
            SigningCertSelector certificateSelector,
            KeyStorePasswordProvider storePasswordProvider,
            KeyEntryPasswordProvider entryPasswordProvider,
            boolean returnFullChain)
    {
        super(new PlainObjectKeyStoreBuilderCreator(alias, privateKey, certificateChain), certificateSelector, storePasswordProvider, entryPasswordProvider, returnFullChain);
    }

    @Override
    protected KeyStore.ProtectionParameter getKeyProtection(
            String entryAlias,
            X509Certificate entryCert,
            KeyEntryPasswordProvider entryPasswordProvider)
    {
        return new KeyStore.PasswordProtection(PASSWORD.toCharArray());
    }

    private static class PlainObjectKeyStoreBuilderCreator implements KeyStoreBuilderCreator
    {
        private final String alias;
        private final PrivateKey privateKey;
        private final X509Certificate[] certificateChain;

        private PlainObjectKeyStoreBuilderCreator(final String alias, final PrivateKey privateKey, final X509Certificate[] certificateChain)
        {
            this.alias = alias;
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
        }

        @Override
        public KeyStore.Builder getBuilder(KeyStore.ProtectionParameter loadProtection)
        {
            try
            {
                KeyStore ks = KeyStore.getInstance("JKS", "SUN");
                ks.load(null, null);
                ks.setKeyEntry(alias, privateKey, PASSWORD.toCharArray(), certificateChain);
                return KeyStore.Builder.newInstance(ks, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));
            }
            catch (KeyStoreException | NoSuchProviderException | CertificateException | IOException | NoSuchAlgorithmException e)
            {
                throw new ProviderException(e.getMessage());
            }
        }
    }
}
