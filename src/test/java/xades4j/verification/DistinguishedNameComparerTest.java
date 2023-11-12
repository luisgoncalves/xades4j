package xades4j.verification;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import xades4j.providers.X500NameStyleProvider;
import xades4j.providers.impl.DefaultX500NameStyleProvider;
import xades4j.utils.RFC4519ExtensibleStyle;
import xades4j.utils.SignatureServicesTestBase;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author luis
 */
public class DistinguishedNameComparerTest extends SignatureServicesTestBase
{
    public static Collection data() throws Exception
    {
        return List.of(
                // Certificate includes the value of OID.2.5.4.97 as UTF8String
                arguments(
                        "2.5.4.97=#0c0f56415445532d413636373231343939,CN=UANATACA CA1 2016,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona (see current address at www.uanataca.com/address),C=ES",
                        certFromResource("issue166/EMPUBqscdA.cer")
                ),
                arguments(
                        "2.5.4.97=#130f56415445532d413636373231343939,CN=UANATACA CA1 2016,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona (see current address at www.uanataca.com/address),C=ES",
                        certFromResource("issue166/EMPUBqscdA.cer")
                ),
                arguments(
                        "OID.2.5.4.97=VATES-A66721499, CN=UANATACA CA1 2016, OU=TSP-UANATACA, O=UANATACA S.A., L=Barcelona (see current address at www.uanataca.com/address), C=ES",
                        certFromResource("issue166/EMPUBqscdA.cer")
                ),
                arguments(
                        "CN = Itermediate, OU = CC, O = ISEL, C = PT",
                        certFromFile("my/LG.cer")
                ),
                arguments(
                        "C = PT, O = SCEE - Sistema de Certificação Electrónica do Estado, OU = ECEstado, CN = Cartão de Cidadão 001",
                        certFromFile("pt/ECQualifSigCC0001.cer")
                )
        );
    }

    private static X509Certificate certFromResource(String resourcePath) throws Exception
    {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream is = DistinguishedNameComparerTest.class.getResourceAsStream(resourcePath))
        {
            return (X509Certificate) certFactory.generateCertificate(is);
        }
    }

    private static X509Certificate certFromFile(String filePath) throws Exception
    {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream is = new FileInputStream(toPlatformSpecificCertDirFilePath(filePath)))
        {
            return (X509Certificate) certFactory.generateCertificate(is);
        }
    }

    private final RFC4519ExtensibleStyle nameStyle;
    private final X500NameStyleProvider x500NameStyleProvider;

    public DistinguishedNameComparerTest() throws IOException
    {
        this.nameStyle = new RFC4519ExtensibleStyle();
        this.x500NameStyleProvider = new DefaultX500NameStyleProvider(this.nameStyle);
    }

    @ParameterizedTest
    @MethodSource("data")
    void canCompare(String issuerDn, X509Certificate cert)
    {
        X500Principal principal = cert.getIssuerX500Principal();
        DistinguishedNameComparer comparer = new DistinguishedNameComparer(this.nameStyle, this.x500NameStyleProvider);

        assertTrue(comparer.areEqual(principal, issuerDn));
    }
}
