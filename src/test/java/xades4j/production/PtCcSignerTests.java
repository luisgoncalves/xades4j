package xades4j.production;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.KeyStoreKeyingDataProvider;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

public class PtCcSignerTests extends SignerTestBase
{
    @Test
    public void testSignTPtCC() throws Exception
    {
        System.out.println("signTPtCitizenCard");
        assumePtCcPkcs11OnWindows();

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        PKCS11KeyStoreKeyingDataProvider ptccKeyingDataProv = new PKCS11KeyStoreKeyingDataProvider(
                PTCC_PKCS11_LIB_PATH, "PT_CC",
                new FirstCertificateSelector(), null, null, false);

        SignerT signer = (SignerT) new XadesTSigningProfile(ptccKeyingDataProv).withAlgorithmsProviderEx(PtCcAlgorithmsProvider.class).newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.t.bes.ptcc.xml");
    }

    @Test
    public void testSignBesPtCCWindowsMy() throws Exception
    {
        System.out.println("signBESPtCitizenCardWindowsMy");
        assumePtCcPkcs11OnWindows();

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        KeyStoreKeyingDataProvider windowsMyKeyingDataProv = new WindowsMyKeyingDataProvider();

        XadesSigner signer = new XadesBesSigningProfile(windowsMyKeyingDataProv).withAlgorithmsProviderEx(PtCcAlgorithmsProvider.class).newSigner();
        new Enveloped(signer).sign(elemToSign);
    }

    private static class WindowsMyKeyingDataProvider extends KeyStoreKeyingDataProvider
    {
        public WindowsMyKeyingDataProvider()
        {
            super(new KeyStoreBuilderCreator()
            {
                @Override
                public KeyStore.Builder getBuilder(KeyStore.ProtectionParameter loadProtection)
                {
                    return KeyStore.Builder.newInstance("Windows-MY", null, loadProtection);
                }
            }, new SigningCertSelector()
            {
                @Override
                public X509Certificate selectCertificate(List<X509Certificate> availableCertificates)
                {
                    for (X509Certificate c : availableCertificates)
                    {
                        if (c.getIssuerDN().getName().contains("EC de Assinatura Digital"))
                        {
                            return c;
                        }
                    }

                    throw new RuntimeException("Cannot find PT CC certificate");
                }
            }, new DirectPasswordProvider(""), null, true);
        }

        @Override
        protected KeyStore.ProtectionParameter getKeyProtection(String entryAlias, X509Certificate entryCert, KeyEntryPasswordProvider entryPasswordProvider)
        {
            return new KeyStore.PasswordProtection(null);
        }
    }
}
