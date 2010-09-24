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

/**
 * Support for signature verification.
 * <p>
 * The entry points for producing a signature is the {@link xades4j.verification.XadesVerificationProfile}
 * class which enables the creation of a {@link xades4j.verification.XadesVerifier}.
 * The library supports verification of XAdES-BES, XAdES-EPES, XAdES-T and XAdES-C.
 * <p>
 * A signature being verified can also be augmented to XAdES-T and XAdES-C.
 */
package xades4j.verification;

