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
package xades4j.providers.impl;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;

import xades4j.providers.CertificateValidationProvider;

/**
 * Implementation of {@code CertificateValidationProvider} using a PKIX
 * {@code CertPathBuilder}.
 * <p>
 * Since the Java's PKIX API doesn't allow to access the CRLs used in the certification
 * path validation, this is manually done. There has to be a CRL for each issuer
 * in the path which is valid at the moment of validation (signature and date).
 * @author Hubert Kario
 */
public class PKIXCertificateValidationProvider
        extends PKIXCertificateValidationProviderBase
        implements CertificateValidationProvider
{
    private static final int DEFAULT_MAX_PATH_LENGTH = 6;

    /**
     * Initializes a new instance that uses the specified JCE providers for CertPathBuilder
     * and Signature.
     * @param trustAnchors the keystore with the trust-anchors ({@code TrustedCertificateEntry})
     * @param revocationEnabled whether revocation is enabled
     * @param maxPathLength the maximum length of the certification paths
     * @param certPathBuilderProvider the CertPathBuilder provider
     * @param signatureProvider the Signature provider
     * @param intermCertsAndCrls a set of {@code CertStore}s that contain certificates to be
     *      used in the construction of the certification path. May contain CRLs to be used
     *      if revocation is enabled
     * @see xades4j.utils.FileSystemDirectoryCertStore
     * @throws NoSuchAlgorithmException if there is no provider for PKIX CertPathBuilder
     */
    public PKIXCertificateValidationProvider(
            KeyStore trustAnchors,
            boolean revocationEnabled,
            int maxPathLength,
            String certPathBuilderProvider,
            String signatureProvider,
            CertStore[] intermCertsAndCrls)
                    throws NoSuchAlgorithmException, NoSuchProviderException
    {
        super(trustAnchors, revocationEnabled, maxPathLength, certPathBuilderProvider,
                signatureProvider, intermCertsAndCrls);
    }

    /**
     * Initializes a new instance that uses the specified JCE providers for CertPathBuilder
     * and Signature.
     * @param trustAnchors the keystore with the trust-anchors ({@code TrustedCertificateEntry})
     * @param revocationEnabled whether revocation is enabled
     * @param certPathBuilderProvider the CertPathBuilder provider
     * @param signatureProvider the Signature provider
     * @param intermCertsAndCrls a set of {@code CertStore}s that contain certificates to be
     *      used in the construction of the certification path. May contain CRLs to be used
     *      if revocation is enabled
     * @see xades4j.utils.FileSystemDirectoryCertStore
     * @throws NoSuchAlgorithmException if there is no provider for PKIX CertPathBuilder
     */
    public PKIXCertificateValidationProvider(
            KeyStore trustAnchors,
            boolean revocationEnabled,
            String certPathBuilderProvider,
            String signatureProvider,
            CertStore... intermCertsAndCrls)
                    throws NoSuchAlgorithmException, NoSuchProviderException
    {
        this(trustAnchors, revocationEnabled, DEFAULT_MAX_PATH_LENGTH, certPathBuilderProvider, signatureProvider, intermCertsAndCrls);
    }

    /**
     * Initializes a new instance that uses the specified JCE provider for both
     * CertPathBuilder and Signature.
     * @param trustAnchors the keystore with the trust-anchors ({@code TrustedCertificateEntry})
     * @param revocationEnabled whether revocation is enabled
     * @param maxPathLength the maximum length of the certification paths
     * @param jceProvider the CertPathBuilder and Signature provider
     * @param intermCertsAndCrls a set of {@code CertStore}s that contain certificates to be
     *      used in the construction of the certification path. May contain CRLs to be used
     *      if revocation is enabled
     * @see xades4j.utils.FileSystemDirectoryCertStore
     * @throws NoSuchAlgorithmException if there is no provider for PKIX CertPathBuilder
     */
    public PKIXCertificateValidationProvider(
            KeyStore trustAnchors,
            boolean revocationEnabled,
            int maxPathLength,
            String jceProvider,
            CertStore... intermCertsAndCrls) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        this(trustAnchors, revocationEnabled, maxPathLength, jceProvider, jceProvider, intermCertsAndCrls);
    }

    /**
     * Initializes a new instance that uses the specified JCE provider for both
     * CertPathBuilder and Signature.
     * @param trustAnchors the keystore with the trust-anchors ({@code TrustedCertificateEntry})
     * @param revocationEnabled whether revocation is enabled
     * @param jceProvider the CertPathBuilder and Signature provider
     * @param intermCertsAndCrls a set of {@code CertStore}s that contain certificates to be
     *      used in the construction of the certification path. May contain CRLs to be used
     *      if revocation is enabled
     * @see xades4j.utils.FileSystemDirectoryCertStore
     * @throws NoSuchAlgorithmException if there is no provider for PKIX CertPathBuilder
     */
    public PKIXCertificateValidationProvider(
            KeyStore trustAnchors,
            boolean revocationEnabled,
            String jceProvider,
            CertStore... intermCertsAndCrls) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        this(trustAnchors, revocationEnabled, DEFAULT_MAX_PATH_LENGTH, jceProvider, intermCertsAndCrls);
    }

    /**
     * Initializes a new instance without specifying the JCE providers for CertPathBuilder
     * and Signature.
     * @param trustAnchors the keystore with the trust-anchors ({@code TrustedCertificateEntry})
     * @param revocationEnabled whether revocation is enabled
     * @param maxPathLength the maximum length of the certification paths
     * @param intermCertsAndCrls a set of {@code CertStore}s that contain certificates to be
     *      used in the construction of the certification path. May contain CRLs to be used
     *      if revocation is enabled
     * @see xades4j.utils.FileSystemDirectoryCertStore
     * @throws NoSuchAlgorithmException if there is no provider for PKIX CertPathBuilder
     */
    public PKIXCertificateValidationProvider(
            KeyStore trustAnchors,
            boolean revocationEnabled,
            int maxPathLength,
            CertStore... intermCertsAndCrls) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        this(trustAnchors, revocationEnabled, maxPathLength, null, null, intermCertsAndCrls);
    }

    /**
     * Initializes a new instance without specifying the JCE providers for CertPathBuilder
     * and Signature.
     * @param trustAnchors the keystore with the trust-anchors ({@code TrustedCertificateEntry})
     * @param revocationEnabled whether revocation is enabled
     * @param intermCertsAndCrls a set of {@code CertStore}s that contain certificates to be
     *      used in the construction of the certification path. May contain CRLs to be used
     *      if revocation is enabled
     * @see xades4j.utils.FileSystemDirectoryCertStore
     * @throws NoSuchAlgorithmException if there is no provider for PKIX CertPathBuilder
     */
    public PKIXCertificateValidationProvider(
            KeyStore trustAnchors,
            boolean revocationEnabled,
            CertStore... intermCertsAndCrls) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        this(trustAnchors, revocationEnabled, DEFAULT_MAX_PATH_LENGTH, null, null, intermCertsAndCrls);
    }

    @Override
    protected void addImplSpecificPKIXBuilderParams(PKIXBuilderParameters pkixbp)
    {
        // no implementation specific validators
        return;
    }

}
