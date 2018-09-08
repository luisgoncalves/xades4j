/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

/**
 * @deprecated
 * This interface is deprecated and might be removed in future versions.
 * @see xades4j.production.BasicSignatureOptions
 * 
 * @author Luís
 */
public interface BasicSignatureOptionsProvider
{
    /**
     * @deprecated the interface is deprecated
     * 
     * Indicates whether the signing certificate, the subject name and issuer/serial
     * should be included within {@code ds:KeyInfo}.
     * @return {@code true} if the certificate should be included; false otherwise
     */
    boolean includeSigningCertificate();

    /**
     * @deprecated the interface is deprecated
     * 
     * Indicates whether a {@code ds:KeyValue} element containing the public key's
     * value should be included in {@code ds:KeyInfo}.
     * @return {@code true} if the public key should be included; false otherwise
     */
    boolean includePublicKey();

    /**
     * @deprecated the interface is deprecated
     * 
     * Indicates whether the signature should cover the {@code ds:X509Certificate}
     * element containing the signing certificate. This is only considered if
     * {@link #includeSigningCertificate()} returns {@code true}.
     * @return {@code true} if the certificate should be signed; false otherwise
     */
    boolean signSigningCertificate();
}
