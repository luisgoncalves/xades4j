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

import org.w3c.dom.Element;
import xades4j.XAdES4jException;
import xades4j.production.XadesSignatureFormatExtender;

/**
 * Interface for a verifier of signatures. The features of the verification process
 * depend on the profile configuration.
 * <p>
 * The signature must contain a {@code KeyInfo} element with one {@code X509Data}
 * element. If more are present, they are ignored, because the data relating to
 * the signing certificate must be within a single {@code X509Data}.
 * The {@code X509Data} element must contain at least one element that identifies
 * the signing certificate, such as {@code X509IssuerSerial}, {@code X509SubjectName}
 * or the {@code X509Certificate} itself. The elements are considered in that order.
 * If {@code X509IssuerSerial} and {@code X509SubjectName} are not present, the
 * first {@code X509Certificate} is used as signing certificate. Nevertheless,
 * all the certificates are collected to be used on the certification path.
 * <p>
 * All the exceptions defined in the current package may be thrown during validation.
 * They are organized as a tree which means that one can go from rough to fine-grained
 * handling by catching exceptions in the different branches/depths of the tree.
 * <p>
 * With its default configuration the library supports verification of signatures
 * up to XAdES-C. The format can be extended after verification through the {@link #verify(org.w3c.dom.Element, xades4j.verification.SignatureSpecificVerificationOptions, xades4j.production.XadesSignatureFormatExtender, xades4j.verification.XAdESForm)  verify}
 * method, even though extended formats cannot be validated afterwards.
 * @see XadesVerificationProfile
 * @author Luís
 */
public interface XadesVerifier
{
    /**
     * Verifies a signature.
     * @param signatureElem the element containing the signature; must have an Id
     * @param verificationOptions signature verification options. If {@code null},
     *      default options are used
     * @return the verification result
     *
     * @see xades4j.verification.SignatureSpecificVerificationOptions
     * @throws XAdES4jException if an error eccurs, including if signature verification fails
     * @throws NullPointerException if {@code signatureElem} is {@code null}
     */
    public XAdESVerificationResult verify(
            Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions) throws XAdES4jException;

    /**
     * Verifies a signature and extends its format if needed.
     * <p>
     * Note that, due to the library's internal design, the properties being addedd
     * to a signature cannot have dependencies on each other because the XML for
     * a given set of properties is generated at the same time, after gathering
     * all the data needed to the properties. For instance, it's not possible to
     * correctly add properties from XAdES-C and XAdES-X t the same time, as the
     * last need the first's XML structure. This imposes some restrictions on the
     * format extensions. Valid transitions are (actual signature form -> form
     * after extension):
     * <ul>
     *  <li>BES/EPES -> T</li>
     *  <li>BES/EPES -> C</li>
     *  <li>T -> C</li>
     *  <li>C -> X</li>
     *  <li>C -> X-L</li>
     *  <li>X -> X-L (not supported by default because X cannot be verified)</li>
     *  <li>X-L -> A (not supported by default because X-L cannot be verified)</li>
     * </ul>
     * Note that the {@code XadesSignatureFormatExtender} can also be used separately,
     * but no checks are made to ensure that the signature has the appropriate
     * properties (form) to be extended with other properties. This can be used
     * to created XAdES-A.
     * <p>
     * The generated XAdES-X is type 1, with one {@code SigAndRefsTimeStamp} property.
     * <p>
     * <b>Limitations</b>: XAdES-C won't include the {@code AttributeCertificateRefs}
     * and {@code AttributeRevocationRefs} properties. XAdES-X-L won't include the
     * {@code AttrAuthoritiesCertValues} and {@code AttributeRevocationValues} properties.
     *
     * @param signatureElem the element containing the signature; must have an Id
     * @param verificationOptions signature verification options. If {@code null},
     *      default options are used
     * @param formatExtender the extender used to add the new unsigned properties
     * @param minForm the minimum format that the signature should have; if the
     *      original signature has a 'lower' format, the extender is used
     * @return the verification result
     *
     * @see xades4j.production.XadesFormatExtenderProfile
     * @see xades4j.production.XadesSignatureFormatExtender
     * @see xades4j.verification.SignatureSpecificVerificationOptions
     * @throws XAdES4jException if an error eccurs, including if signature verification fails
     * @throws NullPointerException if any parameter is {@code null}
     */
    public XAdESVerificationResult verify(
            Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions,
            XadesSignatureFormatExtender formatExtender,
            XAdESForm minForm) throws XAdES4jException;
}
