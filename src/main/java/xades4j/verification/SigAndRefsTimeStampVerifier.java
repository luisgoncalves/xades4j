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
package xades4j.verification;

import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.inject.Inject;

import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.data.SigAndRefsTimeStampData;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.utils.DOMHelper;
import xades4j.utils.TimeStampDigestInput;
import xades4j.utils.TimeStampDigestInputFactory;

/**
 * Verifier for the XAdES-X time stamp property - SigAndRefsTimeStamp
 * XAdES v1.4.2 G.2.2.16.2.3
 *
 * @author Hubert Kario
 */
public class SigAndRefsTimeStampVerifier extends
        TimeStampVerifierBase<SigAndRefsTimeStampData>
{
    @Inject
    public SigAndRefsTimeStampVerifier(
            TimeStampVerificationProvider timeStampVerifier,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(timeStampVerifier, timeStampDigestInputFactory,
                SigAndRefsTimeStampProperty.PROP_NAME);
    }

    @Override
    protected QualifyingProperty addPropSpecificTimeStampInputAndCreateProperty(
            SigAndRefsTimeStampData propData, Element location,
            TimeStampDigestInput digestInput,
            QualifyingPropertyVerificationContext ctx)
            throws CannotAddDataToDigestInputException,
            TimeStampVerificationException
    {
        // TimeStamp is taken over SignatureValue element
        Element sigValueElem = DOMHelper.getFirstDescendant(ctx.getSignature()
                .getElement(), Constants.SignatureSpecNS,
                Constants._TAG_SIGNATUREVALUE);
        digestInput.addNode(sigValueElem);

        /*
         * "Take each one of the signed properties and not property elements in
         * the signature that the normative part dictates that must be
         * time-stamped, in the order specified in the normative clause defining
         * the time-stamp token container type. Canonicalize them and
         * concatenate the resulting bytes in one octet stream. If the
         * CanonicalizationMethod element of the property is present, use it for
         * canonicalizing. Otherwise, use the standard canonicalization method
         * as specified by XMLDSIG."
         *
         * XAdES 1.4.2, section G.2.2.16.2.3, Implicit mechanism: "
         * 1) In step 4) the verifier should check that the CompleteCertificateRefs and
         *    CompleteRevocationRefs properties are present in the signature. She
         *    should also check that they and, if present, SignatureTimeStamp,
         *    AttributeCertificateRefs and AttributeRevocationRefs, appear before
         *    SigAndRefsTimeStamp.
         * 2) In step 5), the verifier should take the aforementioned properties in
         *    their order of appearance within the signature."
         */

        if (location == null) // use fallback mechanism
        {
            // XXX legacy code, to be removed when whole library is using new
            // hybrid verifier

            // next elements that should have been timestamped are all
            // SignatureTimeStamps
            // there may be no SignatureTimeStamps
            NodeList signatureTimeStamps = ctx
                    .getSignature()
                    .getElement()
                    .getElementsByTagNameNS(
                            SignatureTimeStampProperty.XADES_XMLNS,
                            SignatureTimeStampProperty.PROP_NAME);
            for (int i = 0; i < signatureTimeStamps.getLength(); i++)
            {
                Element timeStampElem = (Element) signatureTimeStamps.item(i);
                digestInput.addNode(timeStampElem);
            }

            // then CompleteCertificateRefs
            Element completeCertificateRefsElem = DOMHelper.getFirstDescendant(
                    ctx.getSignature().getElement(),
                    CompleteCertificateRefsProperty.XADES_XMLNS,
                    CompleteCertificateRefsProperty.PROP_NAME);
            digestInput.addNode(completeCertificateRefsElem);

            // ...and CompleteRevocationRefs
            Element completeRevocationRefsElem = DOMHelper.getFirstDescendant(
                    ctx.getSignature().getElement(),
                    CompleteRevocationRefsProperty.XADES_XMLNS,
                    CompleteRevocationRefsProperty.PROP_NAME);
            digestInput.addNode(completeRevocationRefsElem);

            // AttributeCertificateRefs are optional
            Element attributeCertificateRefs = DOMHelper.getFirstDescendant(ctx
                    .getSignature().getElement(),
                    CompleteRevocationRefsProperty.XADES_XMLNS,
                    "AttributeCertificateRefs");
            if (attributeCertificateRefs != null)
                throw new CannotAddDataToDigestInputException(new Exception(
                        "Can't verify SigAndRefsTimeStamp: "
                                + "AttributeCertificateRefs is unsupported"));

            // AttributeRevocationRefs are optional
            Element attributeRevocationRefs = DOMHelper.getFirstDescendant(ctx
                    .getSignature().getElement(),
                    CompleteRevocationRefsProperty.XADES_XMLNS,
                    "AttributeRevocationRefs");
            if (attributeRevocationRefs != null)
                throw new CannotAddDataToDigestInputException(new Exception(
                        "Can't verify SigAndRefsTimeStamp: "
                                + "AttributeRevocationRefs is unsupported"));

            return new SigAndRefsTimeStampProperty();
        } else {
            // TODO write test for document with SigAndRefsTimeStamp but no
            // SignatureTimeStamp

            // remember whatever we found mandatory elements
            boolean foundCompleteRevocRefs = false;
            boolean foundCompleteCertRefs = false;

            // iterate over elements in order in which they are present in XML
            for (Element elem = DOMHelper.getFirstChildElement(location
                    .getParentNode()); elem != location; elem = DOMHelper
                    .getNextSiblingElement(elem))
            {
                if (isElementMatchingProperty(elem,
                        SignatureTimeStampProperty.class))
                {
                    // there are no specific requirements for SignatureTimeStamp
                    // so just add them
                    digestInput.addNode(elem);
                    // TODO check if there are no SignatureTimestamps *after*
                    // SigAndRefsTimeStamp
                } else if (isElementMatchingProperty(elem,
                        CompleteCertificateRefsProperty.class))
                {
                    // there must be exactly one CompleteCertificateRefs element
                    if (foundCompleteCertRefs)
                        throw new CannotAddDataToDigestInputException(
                                new Exception(
                                        "Duplicate CompleteCertificateRefs property"
                                                + " in Signature"));
                    foundCompleteCertRefs = true;
                    digestInput.addNode(elem);
                    // TODO check if there are no CompleteCertificateRefs
                    // *after* SigAndRefsTimeStamp
                } else if (isElementMatchingProperty(elem,
                        CompleteRevocationRefsProperty.class))
                {
                    // there must be exactly one CompleteRevocationRefs element
                    if (foundCompleteRevocRefs)
                        throw new CannotAddDataToDigestInputException(
                                new Exception(
                                        "Duplicate CompleteRevocationRefs property"
                                                + " in Singature"));
                    foundCompleteRevocRefs = true;
                    digestInput.addNode(elem);
                    // TODO check if there are no CompleteRevocationRefs *after*
                    // SigAndRefsTimeStamp
                } else if (elem.getLocalName().equalsIgnoreCase(
                        "AttributeCertificateRefs")
                        && elem.getNamespaceURI().equalsIgnoreCase(
                                QualifyingProperty.XADES_XMLNS))
                {
                    // TODO implement AttributeCertificateRefs support
                    throw new CannotAddDataToDigestInputException(
                            new Exception("Can't verify SigAndRefsTimeStamp: "
                                    + "AttributeCertificateRefs is unsupported"));
                } else if (elem.getLocalName().equalsIgnoreCase(
                        "AttributeRevocationRefs")
                        && elem.getNamespaceURI().equalsIgnoreCase(
                                QualifyingProperty.XADES_XMLNS))
                {
                    // TODO implement AttributeRevocationRefs support
                    throw new CannotAddDataToDigestInputException(
                            new Exception("Can't verify SigAndRefsTimeStamp: "
                                    + "AttributeRevocationRefs is unsupported"));
                } // else: ignore other properties
            }

            if (foundCompleteRevocRefs && foundCompleteCertRefs)
                return new SigAndRefsTimeStampProperty();
            else
                throw new CannotAddDataToDigestInputException(new Exception(
                        "Missing mandatory properties: CompleteCertificateRefs"
                                + " or CompleteRevocationRefs"));
        }
    }

    private boolean isElementMatchingProperty(Element elem,
            Class<? extends QualifyingProperty> prop)
    {
        try
        {
            return elem.getLocalName().equalsIgnoreCase(
                    (String) prop.getField("PROP_NAME").get(null))
                    && elem.getNamespaceURI().equalsIgnoreCase(
                            (String) prop.getField("XADES_XMLNS").get(null));
        } catch (IllegalArgumentException e)
        {
            e.printStackTrace();
            throw new InternalError("Wrong property class");
        } catch (SecurityException e)
        {
            e.printStackTrace();
            throw new InternalError("Wrong property class");
        } catch (IllegalAccessException e)
        {
            e.printStackTrace();
            throw new InternalError("Wrong property class");
        } catch (NoSuchFieldException e)
        {
            e.printStackTrace();
            throw new InternalError("Wrong property class");
        }
    }
}
