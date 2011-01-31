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
package xades4j.verification;

import com.google.inject.Inject;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.CertRef;
import xades4j.properties.data.CompleteCertificateRefsData;
import xades4j.providers.MessageDigestEngineProvider;

/**
 * XAdES G.2.2.12
 * @author Luís
 */
class CompleteCertRefsVerifier implements QualifyingPropertyVerifier<CompleteCertificateRefsData>
{
    private final MessageDigestEngineProvider messageDigestProvider;

    @Inject
    public CompleteCertRefsVerifier(
            MessageDigestEngineProvider messageDigestProvider)
    {
        this.messageDigestProvider = messageDigestProvider;
    }

    @Override
    public QualifyingProperty verify(
            CompleteCertificateRefsData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        List<X509Certificate> caCerts = ctx.getCertChainData().getCertificateChain();
        caCerts = caCerts.subList(1, caCerts.size());
        Collection<CertRef> caCertRefs = propData.getCertRefs();

        // "Check that there are no references to certificates out of those that
        // are part of the certification path."

        for (X509Certificate caCert : caCerts)
        {
            CertRef caRef = CertRefUtils.findCertRef(caCert, caCertRefs);
            if (null == caRef)
                throw new CompleteCertRefsCertNotFoundException(caCert);
            try
            {
                CertRefUtils.checkCertRef(caRef, caCert, messageDigestProvider);
            } catch (CertRefUtils.InvalidCertRefException ex)
            {
                throw new CompleteCertRefsReferenceException(caCert, caRef, ex.getMessage());
            }
        }

        return new CompleteCertificateRefsProperty(Collections.unmodifiableList(caCerts));
    }
}
