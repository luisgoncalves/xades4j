package xades4j.providers;

import javax.security.auth.x500.X500Principal;

/**
 * <b>Experimental API</b>. It may be changed or removed in future releases.
 * 
 * @author Artem R. Romanenko
 * @version 06.08.18
 */
public interface X500NameStyleProvider
{
    /**
     * Parse a DN string.
     * @param dn
     * @return the parsed DN
     * @exception IllegalArgumentException if the name is invalid
     */
    X500Principal fromString(String dn);

    /**
     * Get a DN string.
     * @param dn
     * @return the DN string
     */
    String toString(X500Principal dn);
}
