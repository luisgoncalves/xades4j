package xades4j.utils;

import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;

/**
 * @author Artem R. Romanenko
 * @version 30.07.18
 */

public class Issue157Test {

    private static final String NAME_SIMPLE ="C=CO,L=Bogota D.C.,O=Andes SCD.,OU=Division de certificacion entidad final,CN=CA ANDES SCD S.A. Clase II, E=info@andesscd.com.co";
    private static final String NAME_SIMPLE_NORMAL ="C=CO,L=Bogota D.C.,O=Andes SCD.,OU=Division de certificacion entidad final,CN=CA ANDES SCD S.A. Clase II, EMAILADDRESS=info@andesscd.com.co";
    private static final String NAME_CANONICAL ="C=CO,L=Bogota D.C.,O=Andes SCD.,OU=Division de certificacion entidad final,CN=CA ANDES SCD S.A. Clase II, 1.2.840.113549.1.9.1=#1614696e666f40616e6465737363642e636f6d2e636f";

    @Test(expected = Exception.class)
    public void error(){
        new X500Principal(NAME_SIMPLE);
    }
    @Test
    public void normal(){
        new X500Principal(NAME_CANONICAL);
        new X500Principal(NAME_SIMPLE_NORMAL);

    }
    @Test
    public void normalWithExtendKeywords()
    {
        X500Principal name1 = RfcUtils.parseX500Principal(NAME_CANONICAL);
        X500Principal name2 = RfcUtils.parseX500Principal(NAME_SIMPLE_NORMAL);
        RfcUtils.addSymbol("1.2.840.113549.1.9.1","E");
        X500Principal name3 = RfcUtils.parseX500Principal(NAME_SIMPLE);
        Assert.assertEquals(name1,name2);
        Assert.assertEquals(name1,name3);
    }

}

