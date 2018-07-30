package xades4j.utils;

import org.bouncycastle.asn1.x500.X500Name;

import javax.security.auth.x500.X500Principal;
import java.util.Map;

/**
 * @author Artem R. Romanenko
 * @version 02/04/2018
 */
public class RfcUtils {
    public static String toRfc4514(X500Principal x500Principal) {
        return RFC4519ExtendedStyle.INSTANCE.toString(X500Name.getInstance(x500Principal.getEncoded()));
    }
    public static void addSymbol(String oid,String... names){
        RFC4519ExtendedStyle.INSTANCE.addSymbol(oid,names);
    }

    public static Map<String,String> getKeywordsMap(){
        return RFC4519ExtendedStyle.INSTANCE.getKeywordsMap();
    }

    public static X500Principal parseX500Principal(String dn){
        return new X500Principal(dn,getKeywordsMap());
    }
}