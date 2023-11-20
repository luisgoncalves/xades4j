package xades4j.verification;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xades4j.utils.SignatureServicesTestBase;

import javax.security.auth.x500.X500Principal;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Investigation for <a href="https://github.com/luisgoncalves/xades4j/issues/166">issue 166</a>.
 * @author luis
 */
class Issue166Test extends SignatureServicesTestBase
{
    private final String dnUtf8 = "2.5.4.97=#0c0f56415445532d413636373231343939,CN=UANATACA CA1 2016,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona (see current address at www.uanataca.com/address),C=ES";
    private final String dnPrintable = "2.5.4.97=#130f56415445532d413636373231343939,CN=UANATACA CA1 2016,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona (see current address at www.uanataca.com/address),C=ES";
    private final String dnPlain = "OID.2.5.4.97=VATES-A66721499, CN=UANATACA CA1 2016, OU=TSP-UANATACA, O=UANATACA S.A., L=Barcelona (see current address at www.uanataca.com/address), C=ES";

    private X509Certificate cert;

    @BeforeEach
    public void setUp() throws Exception
    {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        // Certificate includes the value of OID.2.5.4.97 as UTF8String
        try(InputStream is = getClass().getResourceAsStream("issue166/EMPUBqscdA.cer"))
        {
            cert = (X509Certificate) certFactory.generateCertificate(is);
        }
    }

    @Test
    void javaCannotCompareStrings() throws Exception
    {
        X500Principal principal1 = new X500Principal(dnUtf8);
        X500Principal principal2 = new X500Principal(dnPrintable);
        X500Principal principal3 = new X500Principal(dnPlain);

      assertNotEquals(principal1, principal2);
      assertNotEquals(principal1, principal3);
    }
    
    @Test
    void javaCanComparePrintableAndPlainStrings() throws Exception
    {
        X500Principal principal1 = new X500Principal(dnPrintable);
        X500Principal principal2 = new X500Principal(dnPlain);

        assertEquals(principal1, principal2);
    }

    @Test
    void javaCannotCompareCertAndPrintableString() throws Exception
    {
        X500Principal principal1 = cert.getIssuerX500Principal();
        X500Principal principal2 = new X500Principal(dnPrintable);

      assertNotEquals(principal1, principal2);
    }
    
    @Test
    void javaCanCompareCertAndUtf8String() throws Exception
    {
        X500Principal principal1 = cert.getIssuerX500Principal();
        X500Principal principal2 = new X500Principal(dnUtf8);

      assertEquals(principal1, principal2);
    }
    
    @Test
    void javaCannotCompareCertAndPlainString() throws Exception
    {
        X500Principal principal1 = cert.getIssuerX500Principal();
        X500Principal principal2 = new X500Principal(dnPlain);

      assertNotEquals(principal1, principal2);
    }

    @Test
    void bcCanCompareStrings() throws Exception
    {
        X500Name principal1 = new X500Name(dnUtf8);
        X500Name principal2 = new X500Name(dnPrintable);
        X500Name principal3 = new X500Name(dnPlain);

      assertEquals(principal1, principal2);
      assertEquals(principal1, principal3);
      assertEquals(principal2, principal3);
    }

    @Test
    void bcCanCompareCertAndPrintableString() throws Exception
    {
        X500Name principal1 = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        X500Name principal2 = new X500Name(dnPrintable);

      assertEquals(principal1, principal2);
    }
    
    @Test
    void bcCanCompareCertAndUtf8String() throws Exception
    {
        X500Name principal1 = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        X500Name principal2 = new X500Name(dnUtf8);

      assertEquals(principal1, principal2);
    }
    
    @Test
    void bcCanCompareCertAndPlainString() throws Exception
    {
        X500Name principal1 = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        X500Name principal2 = new X500Name(dnPlain);

      assertEquals(principal1, principal2);
    }
}
