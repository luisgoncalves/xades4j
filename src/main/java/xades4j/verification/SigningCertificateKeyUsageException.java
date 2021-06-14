/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2021 achelos GmbH
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

/**
 * Exception to throw in case a signing certificate has a keyUsage extension
 * that does not allow signing.
 *
 * @author Fiona Klute
 */
public final class SigningCertificateKeyUsageException extends SigningCertificateVerificationException
{

    @Override
    protected String getVerificationMessage()
    {
        return "The keyUsage of the signer certificate provided in the SigningCertificate property does not allow signing.";
    }

}
