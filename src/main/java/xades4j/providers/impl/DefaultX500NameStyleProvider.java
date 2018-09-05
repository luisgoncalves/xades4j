package xades4j.providers.impl;


import org.bouncycastle.asn1.x500.X500Name;
import xades4j.providers.X500NameStyleProvider;
import xades4j.utils.RFC4519ExtensibleStyle;
import xades4j.utils.X500ExtensibleNameStyle;

import javax.security.auth.x500.X500Principal;

/**
 * @author Artem R. Romanenko
 * @version 06.08.18
 */
public class DefaultX500NameStyleProvider implements X500NameStyleProvider
{
    private final X500ExtensibleNameStyle x500ExtensibleNameStyle;
    public DefaultX500NameStyleProvider()
    {
        this(new RFC4519ExtensibleStyle());
    }

    public DefaultX500NameStyleProvider(X500ExtensibleNameStyle x500ExtensibleNameStyle)
    {
        this.x500ExtensibleNameStyle = x500ExtensibleNameStyle;
    }


    @Override
    public X500Principal fromString(String dn)
    {
        return new X500Principal(dn, x500ExtensibleNameStyle.getKeywordMap());
    }

    @Override
    public String toString(X500Principal x500Principal)
    {
        return X500Name.getInstance(x500ExtensibleNameStyle, x500Principal.getEncoded()).toString();
    }
}
