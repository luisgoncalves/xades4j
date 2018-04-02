package xades4j.utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;

import javax.security.auth.x500.X500Principal;

/**
 * @author Artem R. Romanenko
 * @version 02/04/2018
 */
public class RfcUtils {
    public static String toRfc4514(X500Principal x500Principal) {
        return RFC4519Style.INSTANCE.toString(X500Name.getInstance(x500Principal.getEncoded()));
    }
}