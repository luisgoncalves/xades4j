package xades4j.verification;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import xades4j.utils.SignatureServicesTestBase;

/**
 * Investigation for https://github.com/luisgoncalves/xades4j/issues/166.
 * @author luis
 */
public class Issue166Test extends SignatureServicesTestBase
{
    private final String dnUtf8 = "2.5.4.97=#0c0f56415445532d413636373231343939,CN=UANATACA CA1 2016,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona (see current address at www.uanataca.com/address),C=ES";
    private final String dnPrintable = "2.5.4.97=#130f56415445532d413636373231343939,CN=UANATACA CA1 2016,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona (see current address at www.uanataca.com/address),C=ES";
    private final String dnPlain = "OID.2.5.4.97=VATES-A66721499, CN=UANATACA CA1 2016, OU=TSP-UANATACA, O=UANATACA S.A., L=Barcelona (see current address at www.uanataca.com/address), C=ES";

    private X509Certificate cert;

    @Before
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
    public void javaCannotCompareStrings() throws Exception
    {
        X500Principal principal1 = new X500Principal(dnUtf8);
        X500Principal principal2 = new X500Principal(dnPrintable);
        X500Principal principal3 = new X500Principal(dnPlain);

        Assert.assertFalse(principal1.equals(principal2));
        Assert.assertFalse(principal1.equals(principal3));
    }
    
    @Test
    public void javaCanComparePrintableAndPlainStrings() throws Exception
    {
        X500Principal principal1 = new X500Principal(dnPrintable);
        X500Principal principal2 = new X500Principal(dnPlain);

        Assert.assertTrue(principal1.equals(principal2));
    }

    @Test
    public void javaCannotCompareCertAndPrintableString() throws Exception
    {
        X500Principal principal1 = cert.getIssuerX500Principal();
        X500Principal principal2 = new X500Principal(dnPrintable);

        Assert.assertFalse(principal1.equals(principal2));
    }
    
    @Test
    public void javaCanCompareCertAndUtf8String() throws Exception
    {
        X500Principal principal1 = cert.getIssuerX500Principal();
        X500Principal principal2 = new X500Principal(dnUtf8);

        Assert.assertTrue(principal1.equals(principal2));
    }
    
    @Test
    public void javaCannotCompareCertAndPlainString() throws Exception
    {
        X500Principal principal1 = cert.getIssuerX500Principal();
        X500Principal principal2 = new X500Principal(dnPlain);

        Assert.assertFalse(principal1.equals(principal2));
    }

    @Test
    public void bcCanCompareStrings() throws Exception
    {
        X500Name principal1 = new X500Name(dnUtf8);
        X500Name principal2 = new X500Name(dnPrintable);
        X500Name principal3 = new X500Name(dnPlain);

        Assert.assertTrue(principal1.equals(principal2));
        Assert.assertTrue(principal1.equals(principal3));
        Assert.assertTrue(principal2.equals(principal3));
    }

    @Test
    public void bcCanCompareCertAndPrintableString() throws Exception
    {
        X500Name principal1 = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        X500Name principal2 = new X500Name(dnPrintable);

        Assert.assertTrue(principal1.equals(principal2));
    }
    
    @Test
    public void bcCanCompareCertAndUtf8String() throws Exception
    {
        X500Name principal1 = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        X500Name principal2 = new X500Name(dnUtf8);

        Assert.assertTrue(principal1.equals(principal2));
    }
    
    @Test
    public void bcCanCompareCertAndPlainString() throws Exception
    {
        X500Name principal1 = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        X500Name principal2 = new X500Name(dnPlain);

        Assert.assertTrue(principal1.equals(principal2));
    }
}
