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
package xades4j.providers;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import xades4j.verification.UnexpectedJCAException;

/**
 * Used in signature production to get the signing key/certificate.
 * @see xades4j.production.XadesSigningProfile
 * @author Luís
 */
public interface KeyingDataProvider
{
    /**
     * Gets the signing certificate chain to be used in an ongoing signature operation.
     * At least the signing certificate must be present. Other certificates may
     * be present, possibly up to the trust anchor.
     * @return the signing certificate (chain)
     * @throws SigningCertChainException if the signing certificate (chain) couldn't be obtained
     * @throws UnexpectedJCAException when an unexpected platform error occurs
     */
    List<X509Certificate> getSigningCertificateChain() throws SigningCertChainException, UnexpectedJCAException;

    /**
     * Gets the signing key that matches a signing certificate. The certificate
     * supplied to this method is ALWAYS the first of the collection returned in
     * the previous call to {@code getSigningCertificateChain}.
     * @param signingCert the certificate for which the corresponding key should be returned
     * @return the private key that matches {@code signingCert}
     * @throws SigningKeyException if the signing key couldn't be obtained
     * @throws UnexpectedJCAException when an unexpected platform error occurs
     */
    PrivateKey getSigningKey(X509Certificate signingCert) throws SigningKeyException, UnexpectedJCAException;
}
