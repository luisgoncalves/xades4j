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
package xades4j.production;

import xades4j.properties.UnsignedProperties;
import org.apache.xml.security.signature.XMLSignature;
import xades4j.XAdES4jException;

/**
 * Interface for signature enrichment. The features of the enrichment process
 * depend on the profile configuration.
 * <p>
 * The main purpose of {@code XadesSignatureFormatExtender} is to be used in the
 * {@link xades4j.verification.XadesVerifier#verify(org.w3c.dom.Element, xades4j.verification.SignatureSpecificVerificationOptions, xades4j.production.XadesSignatureFormatExtender, xades4j.verification.XAdESForm) verification process}.
 * However, it can also be used separately, but no checks are made on the correctness
 * of the signature. It is user's responsability to ensure that the signature has
 * the appropriate properties (form) to be extended with other properties.
 * @see XadesFormatExtenderProfile
 * @author Luís
 */
public interface XadesSignatureFormatExtender
{
    /**
     * Enrichs a signature with a set of properties. If no properties are specified,
     * no actions are taken.
     * <p>
     * Note that, due to the library's internal design, the properties cannot have
     * dependencies on each other. For instance, one must not add properties from
     * XAdES-C and XAdES-X, as the last need the first's XML structure. In the library,
     * the XML for a given set of properties is generated at the same time, after
     * gathering all the data needed to the properties.
     * @param sig the signature
     * @param props the properties
     * @throws XAdES4jException if an error occurs (see {@link XadesSigner#sign(xades4j.production.SignedDataObjects, org.w3c.dom.Node)})
     */
    void enrichSignature(
            XMLSignature sig,
            UnsignedProperties props) throws XAdES4jException;
}
