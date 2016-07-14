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
 * up to and including XAdES-A. The format can be extended after verification through the
 * {@link #verify(org.w3c.dom.Element, xades4j.verification.SignatureSpecificVerificationOptions, xades4j.production.XadesSignatureFormatExtender, xades4j.verification.XAdESForm)  verify}
 * method.
 * @see XadesVerificationProfile
 * @author Luís
 */
public interface XadesVerifier
{
    /**
     * Verifies a signature. Checks if it is correctly formed, if required properties are
     * present for the detected form, etc.
     * <p>
     * It does <b>not</b> check whatever:
     * <ul>
     *  <li>the complete signature is as as minimal as possible (there is no duplication
     *  of certificates or CRLs)</li>
     *  <li>grace periods for signature and subsequent TimeStamps are preserved</li>
     * </ul>
     * </p><p>
     * <b>Limitations</b>:<br/> XAdES-C won't include the {@code AttributeCertificateRefs}
     * and {@code AttributeRevocationRefs} properties. The library can't verify
     * signatures that use OCSP responses for revocation information source.
     * The library can't verify XAdES-X type 2 documents (the
     * {@code RefsOnlyTimeStamp} property).</p>
     * <br/>
     * @param signatureElem the element containing the signature; must have an {@code Id}
     *      attribute
     * @param verificationOptions signature verification options. If {@code null},
     *      default options are used, see: {@link SignatureSpecificVerificationOptions}
     * @return the verification result (if verification successful)
     *
     * @see xades4j.verification.SignatureSpecificVerificationOptions
     * @throws XAdES4jException if during verification a critical error occurs, causing
     *       signature verification failure. Failure to validate single element if there
     *       are other elements able to provide unbroken chain of time stamps will
     *       <b>not</b> cause an Exception to be thrown.
     * @throws NullPointerException if {@code signatureElem} is {@code null}
     * @see XadesVerifier
     */
    public XAdESVerificationResult verify(
            Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions) throws XAdES4jException;

    /**
     * Verifies a signature and extends its format.
     * <p>
     * Note that, due to the library's internal design, the properties being added
     * to a signature cannot have dependencies on each other because the XML for
     * a given set of properties is generated at the same time, after gathering
     * all the data needed to the properties. For instance, it's not possible to
     * correctly add properties from XAdES-C and XAdES-X at the same time, as the
     * last need the first's XML structure. This imposes some restrictions on the
     * format extensions. To work around this limitation you can first extend the form to
     * XAdES-C form and then to XAdES-X form.
     * </p><p>
     * Valid transitions are (actual signature form -&gt; form after extension):
     * <ul>
     *  <li>BES/EPES -&gt; T</li>
     *  <li>BES/EPES -&gt; C</li>
     *  <li>T -&gt; T</li>
     *  <li>T -&gt; C</li>
     *  <li>T -&gt; X-L (not supported)</li>
     *  <li>C -&gt; X</li>
     *  <li>C -&gt; X-L</li>
     *  <li>X -&gt; X</li>
     *  <li>X -&gt; X-L</li>
     *  <li>X-L -&gt; A</li>
     *  <li>A -&gt; A</li>
     *  <li>A -&gt; A-VD</li>
     * </ul>
     * Note: {@code A-VD} form is an abstract form, that's used inside this library
     * to notify the extender that we want to add {@code TimeStampVerificationData}
     * property. TimeStampVerificationData is used to contain data needed to validate
     * previous TimeStamps. Validation of A-VD form will return the A form so
     * subsequent A-TimeStamping of A-VD form is possible.</p>
     * <p>
     * <b>Caution:</b> While the library allows you to extend BES form to A form with
     * validation data in matter of seconds, this process may not create actually valid
     * signature. This is caused by the fact that law in some countries (and general good
     * practice) dictates presence of grace period (See: ETSI TS 101 903, "XAdES standard"
     * v. 1.4.2, section 4.4.3.2, NOTE 4). This poses time limits on signature form
     * extension. For example, if the grace period is 1h, you may not extend T form to
     * C form earlier than 1h after T form creation (it may be longer if you're unable
     * to obtain CRL published 1h after T form creation). Same issue exists when
     * extending from T form to X-L form, from X form to X-L form and from A form to
     * A-VD form. The lack of actual enforcement of this is caused by lack of support
     * for grace period in underlying interface (Java crypto API) and used cryptographic
     * library (Bouncy Castle).
     * </p>
     * <p>
     * Note that the {@code XadesSignatureFormatExtender} can also be used separately,
     * but then no checks are made to ensure that the signature has the appropriate
     * properties (form) to be extended with other properties.
     * <p>
     * The generated XAdES-X is type 1, with one {@code SigAndRefsTimeStamp} property.
     * <p>
     * <b>Limitations</b>:
     * <ul>
     *  <li>XAdES-C won't include the optional {@code AttributeCertificateRefs}
     * and {@code AttributeRevocationRefs} properties</li>
     *  <li>library can't verify or create signatures that use OCSP responses for
     *    revocation information</li>
     *  <li>library can't verify XAdES-X type 2 or documents that build on it
     *  (the {@code RefsOnlyTimeStamp} property)
     *  </li>
     * </ul>
     *
     * @param signatureElem the element containing the signature; must have an Id
     * @param verificationOptions signature verification options. If {@code null},
     *      default options are used
     * @param formatExtender the extender used to add the new unsigned properties
     * @param minForm the minimum format that the signature should have; if the
     *      original signature has a 'lower' format (as per list above), the extender
     *      is used
     * @return the verification result
     *
     * @see xades4j.production.XadesFormatExtenderProfile
     * @see xades4j.production.XadesSignatureFormatExtender
     * @see xades4j.verification.SignatureSpecificVerificationOptions
     * @throws XAdES4jException if an error occurs, including if signature verification fails
     * @throws NullPointerException if any parameter is {@code null}
     */
    public XAdESVerificationResult verify(
            Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions,
            XadesSignatureFormatExtender formatExtender,
            XAdESForm minForm) throws XAdES4jException;
}
