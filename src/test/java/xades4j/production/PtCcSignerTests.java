package xades4j.production;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.utils.PtCcSigningCertificateSelector;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

public class PtCcSignerTests extends SignerTestBase
{
    @Test
    public void testSignTPtCC() throws Exception
    {
        assumePtCcPkcs11();

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        PKCS11KeyStoreKeyingDataProvider ptccKeyingDataProv = PKCS11KeyStoreKeyingDataProvider
                .builder(PTCC_PKCS11_LIB_PATH, new PtCcSigningCertificateSelector())
                .build();

        XadesSigner signer = new XadesTSigningProfile(ptccKeyingDataProv).newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.t.bes.ptcc.xml");
    }

    @Test
    public void testSignBesPtCCWindowsMy() throws Exception
    {
        assumeWindows();
        assumePtCcPkcs11();

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        KeyStoreKeyingDataProvider windowsMyKeyingDataProv = new WindowsMyKeyingDataProvider();

        XadesSigner signer = new XadesBesSigningProfile(windowsMyKeyingDataProv).newSigner();
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
            }, new SigningCertificateSelector()
            {
                @Override
                public Entry selectCertificate(List<Entry> availableCertificates)
                {
                    for (Entry e : availableCertificates)
                    {
                        if (e.getCertificate().getIssuerDN().getName().contains("EC de Assinatura Digital"))
                        {
                            return e;
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
