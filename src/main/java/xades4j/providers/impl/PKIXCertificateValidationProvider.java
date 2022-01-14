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
package xades4j.providers.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

import xades4j.providers.CannotBuildCertificationPathException;
import xades4j.providers.CannotSelectCertificateException;
import xades4j.providers.CertificateValidationException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.ValidationData;
import xades4j.verification.UnexpectedJCAException;

/**
 * Implementation of {@code CertificateValidationProvider} using a PKIX {@code CertPathBuilder}.
 * <p>
 * Since the Java's PKIX API doesn't allow to access the CRLs used in the certification
 * path validation, this is manually done. There has to be a CRL for each issuer
 * in the path which is valid at the moment of validation (signature and date).
 * <p>
 * The {@link PKIXCertificateValidationProvider#builder(KeyStore)} builder} method can be used to configure and create
 * a new instance.
 *
 * @author Luís
 */
public final class PKIXCertificateValidationProvider implements CertificateValidationProvider
{
    private static final int DEFAULT_MAX_PATH_LENGTH = 6;

    private final KeyStore trustAnchors;
    private final boolean revocationEnabled;
    private final int maxPathLength;
    private final CertStore[] intermCertsAndCrls;
    private final CertPathBuilder certPathBuilder;
    private final String signatureProvider;

    /**
     * Create a builder to configure a new {@link PKIXCertificateValidationProvider}.
     *
     * @param trustAnchors the keystore with the trust-anchors ({@code TrustedCertificateEntry})
     * @return the builder
     */
    public static Builder builder(KeyStore trustAnchors)
    {
        return new Builder(trustAnchors);
    }

    private PKIXCertificateValidationProvider(Builder builder) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        this.trustAnchors = builder.trustAnchors;
        this.revocationEnabled = builder.revocationEnabled;
        this.maxPathLength = builder.maxPathLength;
        this.certPathBuilder = builder.certPathBuilderProvider == null
                ? CertPathBuilder.getInstance("PKIX")
                : CertPathBuilder.getInstance("PKIX", builder.certPathBuilderProvider);
        this.signatureProvider = builder.signatureProvider;
        this.intermCertsAndCrls = builder.certStores;
    }

    @Override
    public ValidationData validate(
            X509CertSelector certSelector,
            Date validationDate,
            Collection<X509Certificate> otherCerts) throws CertificateValidationException, UnexpectedJCAException
    {
        PKIXBuilderParameters builderParams;
        try
        {
            builderParams = new PKIXBuilderParameters(trustAnchors, certSelector);
        }
        catch (KeyStoreException ex)
        {
            throw new CannotBuildCertificationPathException(certSelector, "Trust anchors KeyStore is not initialized", ex);
        }
        catch (InvalidAlgorithmParameterException ex)
        {
            throw new CannotBuildCertificationPathException(certSelector, "Trust anchors KeyStore has no trusted certificate entries", ex);
        }

        PKIXCertPathBuilderResult builderRes;
        try
        {
            // Certificates to be used to build the certification path.
            // - The other certificates from the signature (e.g. from KeyInfo).
            if (otherCerts != null)
            {
                CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(otherCerts);
                CertStore othersCertStore = CertStore.getInstance("Collection", ccsp);
                builderParams.addCertStore(othersCertStore);
            }
            // - The external certificates/CRLs.
            for (int i = 0; i < intermCertsAndCrls.length; i++)
            {
                builderParams.addCertStore(intermCertsAndCrls[i]);
            }

            builderParams.setRevocationEnabled(revocationEnabled);
            builderParams.setMaxPathLength(maxPathLength);
            builderParams.setDate(validationDate);
            builderParams.setSigProvider(this.signatureProvider);

            builderRes = (PKIXCertPathBuilderResult) certPathBuilder.build(builderParams);
        }
        catch (CertPathBuilderException ex)
        {
            throw new CannotBuildCertificationPathException(certSelector, ex.getMessage(), ex);
        }
        catch (InvalidAlgorithmParameterException ex)
        {
            // SHOULD NOT be thrown due to wrong type of parameters.
            // Seems to be thrown when the CertSelector (in builderParams) criteria
            // cannot be applied.
            throw new CannotSelectCertificateException(certSelector, ex);
        }
        catch (NoSuchAlgorithmException ex)
        {
            // SHOULD NOT be thrown.
            throw new UnexpectedJCAException("No provider for Collection CertStore", ex);
        }

        // The cert path returned by the builder ends in a certificate issued by
        // the trust anchor. However, the complete path may be needed for property
        // verification.
        List<X509Certificate> certPath = (List<X509Certificate>) builderRes.getCertPath().getCertificates();
        // - Create a new list since the previous is immutable.
        certPath = new ArrayList<X509Certificate>(certPath);
        // - Add the trust anchor certificate.
        certPath.add(builderRes.getTrustAnchor().getTrustedCert());

        if (revocationEnabled)
        {
            return new ValidationData(certPath, getCRLsForCertPath(certPath, validationDate));
        }
        return new ValidationData(certPath);
    }

    private Collection<X509CRL> getCRLsForCertPath(
            List<X509Certificate> certPath,
            Date validationDate) throws CertificateValidationException
    {
        // Map the issuers certificates in the chain. This is used to know the issuers
        // and later to verify the signatures in the CRLs.
        Map<X500Principal, X509Certificate> issuersCerts = new HashMap<X500Principal, X509Certificate>(certPath.size() - 1);
        for (int i = 0; i < certPath.size() - 1; i++)
        {
            // The issuer of one certificate is the subject of the following one.
            issuersCerts.put(certPath.get(i).getIssuerX500Principal(), certPath.get(i + 1));
        }

        // Select all the CRLs from the issuers involved in the certification path
        // that are valid at the moment.
        X509CRLSelector crlSelector = new X509CRLSelector();
        for (X500Principal issuer : issuersCerts.keySet())
        {
            // - "The issuer distinguished name in the X509CRL must match at least
            //   one of the specified distinguished names."
            crlSelector.addIssuer(issuer);
        }
        // - "The specified date must be equal to or later than the value of the
        //   thisUpdate component of the X509CRL and earlier than the value of the
        //   nextUpdate component."
        crlSelector.setDateAndTime(validationDate);

        Set<X509CRL> crls = new HashSet<X509CRL>();
        try
        {
            // Get the CRLs on each CertStore.
            for (int i = 0; i < intermCertsAndCrls.length; i++)
            {
                Collection storeCRLs = intermCertsAndCrls[i].getCRLs(crlSelector);
                crls.addAll(Collections.checkedCollection(storeCRLs, X509CRL.class));

            }
        }
        catch (CertStoreException ex)
        {
            throw new CertificateValidationException(null, "Cannot get CRLs", ex);
        }

        // Verify the CRLs' signatures. The issuers' certificates were validated
        // as part of the cert path creation.
        for (X509CRL crl : crls)
        {
            try
            {
                X509Certificate crlIssuerCert = issuersCerts.get(crl.getIssuerX500Principal());
                if (null == this.signatureProvider)
                {
                    crl.verify(crlIssuerCert.getPublicKey());
                }
                else
                {
                    crl.verify(crlIssuerCert.getPublicKey(), this.signatureProvider);
                }
            }
            catch (Exception ex)
            {
                throw new CertificateValidationException(null, "Invalid CRL signature from " + crl.getIssuerX500Principal().getName(), ex);
            }
        }
        return crls;
    }

    public static final class Builder
    {
        private final KeyStore trustAnchors;
        private CertStore[] certStores;
        private boolean revocationEnabled;
        private int maxPathLength;
        private String certPathBuilderProvider;
        private String signatureProvider;

        private Builder(KeyStore trustAnchors)
        {
            if (null == trustAnchors)
            {
                throw new NullPointerException("Trust anchors cannot be null");
            }

            this.trustAnchors = trustAnchors;
            this.certStores = new CertStore[0];
            this.revocationEnabled = true;
            this.maxPathLength = DEFAULT_MAX_PATH_LENGTH;
        }

        public PKIXCertificateValidationProvider build() throws NoSuchAlgorithmException, NoSuchProviderException
        {
            return new PKIXCertificateValidationProvider(this);
        }

        /**
         * Sets the {@link CertStore}s that contain intermediate certificates to be used in the construction of the
         * certification path. May contain CRLs to be used if revocation checking is enabled.
         *
         * @param certStores the certificate and CRL stores
         * @return the current instance
         */
        public Builder intermediateCertStores(CertStore... certStores)
        {
            this.certStores = certStores;
            return this;
        }

        /**
         * Sets whether revocation checking should be used. Defaults to {@code true}.
         *
         * @param revocationEnabled {@code true} to check revocation, {@code false} otherwise
         * @return the current instance
         */
        public Builder checkRevocation(boolean revocationEnabled)
        {
            this.revocationEnabled = revocationEnabled;
            return this;
        }

        /**
         * Sets the maximum length of the certification path.
         *
         * @param maxPathLength the maximum length
         * @return the current instance
         */
        public Builder maxPathLength(int maxPathLength)
        {
            this.maxPathLength = maxPathLength;
            return this;
        }

        /**
         * Sets the {@link CertPathBuilder} provider.
         *
         * @param certPathBuilderProvider the provider
         * @return the current instance
         */
        public Builder certPathBuilderProvider(String certPathBuilderProvider)
        {
            this.certPathBuilderProvider = certPathBuilderProvider;
            return this;
        }

        /**
         * Sets the provider for {@link java.security.Signature} objects used when building the certification path.
         *
         * @param signatureProvider the provider
         * @return the current instance
         */
        public Builder signatureProvider(String signatureProvider)
        {
            this.signatureProvider = signatureProvider;
            return this;
        }
    }
}
