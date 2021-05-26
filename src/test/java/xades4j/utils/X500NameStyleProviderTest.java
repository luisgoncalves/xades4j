package xades4j.utils;

import org.junit.Assert;
import org.junit.Test;
import xades4j.providers.X500NameStyleProvider;
import xades4j.providers.impl.DefaultX500NameStyleProvider;

import javax.security.auth.x500.X500Principal;

/**
 *
 * @author Artem R. Romanenko
 * @version 30.07.18
 * @see <a href="https://github.com/luisgoncalves/xades4j/issues/157">Issues-157</a>
 */

public class X500NameStyleProviderTest
{
    private static final String NAME_SIMPLE ="C=CO,L=Bogota D.C.,O=Andes SCD.,OU=Division de certificacion entidad final,CN=CA ANDES SCD S.A. Clase II, E=info@andesscd.com.co";
    private static final String NAME_SIMPLE_NORMAL ="C=CO,L=Bogota D.C.,O=Andes SCD.,OU=Division de certificacion entidad final,CN=CA ANDES SCD S.A. Clase II, EMAILADDRESS=info@andesscd.com.co";
    private static final String NAME_CANONICAL ="C=CO,L=Bogota D.C.,O=Andes SCD.,OU=Division de certificacion entidad final,CN=CA ANDES SCD S.A. Clase II, 1.2.840.113549.1.9.1=#1614696e666f40616e6465737363642e636f6d2e636f";

    @Test(expected = Exception.class)
    public void errorDefaultParsing()
    {
        new X500Principal(NAME_SIMPLE);
    }

    @Test(expected = Exception.class)
    public void errorParsingWithProvider()
    {
        new DefaultX500NameStyleProvider().fromString(NAME_SIMPLE);
    }

    @Test
    public void normal()
    {
        new X500Principal(NAME_CANONICAL);
        new X500Principal(NAME_SIMPLE_NORMAL);
    }

    @Test
    public void normalWithExtendKeywords()
    {
        X500NameStyleProvider x500NameStyleProvider = new DefaultX500NameStyleProvider();
        X500Principal name1 = x500NameStyleProvider.fromString(NAME_CANONICAL);
        X500Principal name2 = x500NameStyleProvider.fromString(NAME_SIMPLE_NORMAL);
        RFC4519ExtensibleStyle es = new RFC4519ExtensibleStyle();
        es.addSymbol("1.2.840.113549.1.9.1","E");
        X500NameStyleProvider x500NameStyleProviderExtend =new DefaultX500NameStyleProvider(es);
        X500Principal name3 = x500NameStyleProviderExtend.fromString(NAME_SIMPLE);
        Assert.assertEquals(name1,name2);
        Assert.assertEquals(name1,name3);
    }

}

