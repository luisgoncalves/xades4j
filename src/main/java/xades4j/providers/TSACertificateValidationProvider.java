/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario -QBS.
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
 * {@link CertificateValidationProvider} made specifically for validating certificates
 * used by Time Stamping Authorities.
 * <p>
 * verify() method should gracefully handle certificates with time stamping extended
 * critical key usage extension.
 * <p>
 * <small>interface made specifically to differentiate verifiers used for signature
 * verification and used for attribute verification (TimeStamps)</small>
 * @author Hubert Kario
 *
 */
public interface TSACertificateValidationProvider extends
        CertificateValidationProvider
{
}
