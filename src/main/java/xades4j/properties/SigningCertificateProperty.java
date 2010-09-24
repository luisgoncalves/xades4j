/*
 *  XAdES4j - A Java library for generation and verification of XAdES signatures.
 *  Copyright (C) 2010 Luis Goncalves.
 * 
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation; either version 2 of the License, or any later version.
 * 
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 *  Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.properties;

import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * The {@code SigningCertificate} property is designed to prevent the simple substitution
 * of the certificate. This property contains references to certificates and digest
 * values computed on them. The certificate used to verify the signature shall be
 * identified in the sequence. Other certificates may be present, possibily up to
 * the point of trust.
 * <p>
 * This is a signed property that qualifies the signature. At most one {@code SigningCertificate}
 * element may be present in the signature.
 * <p>
 * In signature production this property canno be supplied directly because it is
 * mandatory. It is enforced by the {@link xades4j.production.XadesSigner}.
 * @author Luís
 */
public final class SigningCertificateProperty extends SignedSignatureProperty
{
    public static final String PROP_NAME = "SigningCertificate";
    /**/
    private final Collection<X509Certificate> signingCertificateChain;

    public SigningCertificateProperty(
            Collection<X509Certificate> signingCertificateChain)
    {
        this.signingCertificateChain = signingCertificateChain;
    }

    /**
     * Gets the fragment of the certificate chain contained in the property. This
     * is an ordered collection starting at the signing certificate and following
     * the convention of X.509 {@link java.security.cert.CertPath}s. It may contain
     * only one the signing certificate.
     * @return the certificate chain
     */
    public Collection<X509Certificate> getsigningCertificateChain()
    {
        return this.signingCertificateChain;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
