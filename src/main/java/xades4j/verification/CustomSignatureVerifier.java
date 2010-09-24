/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.verification;

/**
 * Interface for custom signature verifiers. Custom verifiers may validate the
 * signature has a whole. They are invoked in the end of signature verification.
 * <p>
 * Custom verifiers are registered through the {@link XadesVerificationProfile#withCustomSignatureVerifier(xades4j.verification.CustomSignatureVerifier)}
 * method.
 * @author Luís
 */
public interface CustomSignatureVerifier
{
    public void verify(
            XAdESVerificationResult verificationData,
            QualifyingPropertyVerificationContext ctx) throws InvalidSignatureException;
}
