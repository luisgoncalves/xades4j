package xades4j.utils;

import org.bouncycastle.asn1.x500.X500NameStyle;

import java.util.Map;

/**
 * @author Artem R. Romanenko
 * @version 06.08.18
 */
public interface X500ExtensibleNameStyle extends X500NameStyle
{
    /**
     *
     * @param oid Object ID
     * @param names Names according to Object ID with order of passing
     */
    void addSymbol(String oid, String... names);

    /**
     *
     * @return an attribute type keyword map, where each key is a keyword String that maps to a corresponding object identifier in String form (a sequence of nonnegative integers separated by periods). The map may be empty but never null.
     * @see javax.security.auth.x500.X500Principal#X500Principal(String, java.util.Map)
     */
    Map<String,String> getKeywordMap();
}
