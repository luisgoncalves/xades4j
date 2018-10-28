/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package xades4j.verification;

import com.google.inject.Inject;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import xades4j.providers.X500NameStyleProvider;

/**
 * <b>Experimental API</b>. It may be changed or removed in future releases.
 *
 * @author luis
 */
class DistinguishedNameComparer
{
    private final X500NameStyleProvider x500NameStyleProvider;
    
    @Inject
    DistinguishedNameComparer(X500NameStyleProvider x500NameStyleProvider)
    {
        this.x500NameStyleProvider = x500NameStyleProvider;
    }

    /**
     * @exception IllegalArgumentException if the DN string is invalid 
     */
    boolean areEqual(X500Principal parsedDn, String stringDn)
    {
        X500Name first = X500Name.getInstance(parsedDn.getEncoded());
        // TODO consider simplifying this by constructing from string and using the configured keyword map
        X500Name second = X500Name.getInstance(this.x500NameStyleProvider.fromString(stringDn).getEncoded());
        return first.equals(second);
    }
}
