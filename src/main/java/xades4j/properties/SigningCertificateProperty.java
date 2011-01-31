/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
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
