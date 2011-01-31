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
 * The {@code CertificateValues} is an optional unsigned property and qualifies
 * the XML signature. There is at most one occurence of this property in the signature.
 * <p>
 * In principle, the {@code CertificateValues} element contains the full set of certificates
 * that have been used to validate the electronic signature, including the signer's
 * certificate. However, it is not necessary to include one of those certificates
 * into this property, if the certificate is already present in the ds:KeyInfo
 * element of the signature.
 * @author Luís
 */
public final class CertificateValuesProperty extends UnsignedSignatureProperty
{
    public static final String PROP_NAME = "CertificateValues";
    private final Collection<X509Certificate> certificates;

    public CertificateValuesProperty(Collection<X509Certificate> certificates)
    {
        if (null == certificates)
            throw new NullPointerException();
        this.certificates = certificates;
    }

    public Collection<X509Certificate> getCertificates()
    {
        return certificates;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
