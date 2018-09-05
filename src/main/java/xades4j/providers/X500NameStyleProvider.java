package xades4j.providers;

import javax.security.auth.x500.X500Principal;


/**
 * @author Artem R. Romanenko
 * @version 06.08.18
 */
public interface X500NameStyleProvider
{
    X500Principal fromString(String dn);
    String toString(X500Principal dn);
}
