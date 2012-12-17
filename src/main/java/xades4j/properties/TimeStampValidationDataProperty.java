/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
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

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * The {@code TimeStampValidationData} is an optional unsigned property that extends
 * the XAdES-A format with information needed to verify previously signed time stamps.
 * There can be multiple occurrences of this property in signature.
 * <p>
 * In principle, the {@code TimeStampValidationData} element contains the full set of
 * certificates and revocation information (CRLs or OCSP responses) that have been used
 * to validate previous time stamp (XAdES-X time stamp in case of first
 * {@code TimeStampValidationData} added after creation of first
 * {@code ArchiveTimeStamp}).
 * @author Hubert Kario
 */
public class TimeStampValidationDataProperty extends UnsignedSignatureProperty
{
    // it is in xadesv141 namespace though!
    public static final String PROP_NAME = "TimeStampValidationData";
    private final Collection<X509Certificate> certificateValues;
    private final Collection<X509CRL> crls;

    /**
     * Both parameters can be {@code null} or empty, but not at the same time
     *
     * @param certificates can be null
     * @param crls can be null
     */
    public TimeStampValidationDataProperty(Collection<X509Certificate> certificates,
            Collection<X509CRL> crls)
    {
        if ((certificates == null && crls == null) ||
                (certificates.isEmpty() && crls.isEmpty()))
            throw new NullPointerException("Both parameters can't be null/empty");

        this.certificateValues = certificates;
        this.crls = crls;
    }

    public Collection<X509CRL> getCrls()
    {
        return crls;
    }

    public Collection<X509Certificate> getCertificates()
    {
        return certificateValues;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }

}
