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

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;

import com.google.inject.Inject;

import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.AttrAuthoritiesCertValuesProperty;
import xades4j.properties.AttributeRevocationValuesProperty;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.data.ArchiveTimeStampData;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.utils.DOMHelper;
import xades4j.utils.TimeStampDigestInput;
import xades4j.utils.TimeStampDigestInputFactory;

public class ArchiveTimeStampVerifier extends
        TimeStampVerifierBase<ArchiveTimeStampData>
{

    @Inject
    public ArchiveTimeStampVerifier(
            TimeStampVerificationProvider timeStampVerifier,
            TimeStampDigestInputFactory timeStampDigestInputFactory)
    {
        super(timeStampVerifier, timeStampDigestInputFactory,
                ArchiveTimeStampProperty.PROP_NAME);
    }

    @Override
    protected QualifyingProperty addPropSpecificTimeStampInputAndCreateProperty(
            ArchiveTimeStampData propData, Element location,
            TimeStampDigestInput digestInput,
            QualifyingPropertyVerificationContext ctx)
            throws CannotAddDataToDigestInputException,
            TimeStampVerificationException
    {
        // Archive time stamp is taken over: References, SignedInfor, SignatureValue,
        // KeyInfo and all UnsignedSignatureProperties in order of appearance

        // References, processed accordingly to XML-DSIG.
        SignedInfo signedInfo = ctx.getSignature().getSignedInfo();
        try
        {
            for (int i=0; i < signedInfo.getLength(); i++)
            {
                Reference ref = signedInfo.item(i);
                digestInput.addReference(ref);
            }
        } catch (XMLSecurityException e)
        {
            throw new CannotAddDataToDigestInputException(e);
        }

        // SignedInfo
        Element e = ctx.getSignature().getSignedInfo().getElement();
        digestInput.addNode(e);

        // SignatureValue.
        e = DOMHelper.getFirstDescendant(
                ctx.getSignature().getElement(),
                Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);
        digestInput.addNode(e);

        // KeyInfo, if present
        KeyInfo ki = ctx.getSignature().getKeyInfo();
        if (ki != null)
            digestInput.addNode(ki.getElement());

        /*
         * XAdES v1.4.2 standard, section G.2.2.16.2.4, implicit mechanism: "
         * 1) Step 5) is performed as indicated. The verifier will take,
         *    among the unsigned properties that appear before the property that
         *    is being verified, those that appear in the following list, and in
         *    their order of appearance: SignatureTimeStamp, CounterSignature,
         *    CompleteCertificateRefs, CompleteRevocationRefs,
         *    AttributeCertificateRefs, AttributeRevocationRefs,
         *    CertificateValues, RevocationValues, SigAndRefsTimeStamp,
         *    RefsOnlyTimeStamp, xadesv141:ArchiveTimeStamp,
         *    xadesv141:TimeStampDataValidation and all the ds:Object elements
         *    different to the one containing the QualifyingProperties."
         *
         * section 8.2.1, item 4), requires the presence of CertificateValues and
         * RevocationValues. If the signature contains other TimeStamps then
         * AttrAuthoritiesCertValues and AttributeRevocationValues must be present,
         * but only if Attribute Authorities don't share CRLs/OCSP or (sub)CAs with
         * Signature. Because of that, we will only require presence of CertValues and
         * RevocationValues.
         */
        boolean certificateValuesPresent = false;
        boolean revocationValuesPresent = false;
        // TODO test with document having only XAdES-X-L (above ones) properties

        // requirements from SigAndRefsTimeStamp, only enforce singletonity, not presence
        boolean completeCertRefsPresent = false;
        boolean completeRevocRefsPresent = false;

        // all previous properties in order of appearance
        for(Element elem = DOMHelper.getFirstChildElement(location.getParentNode());
                elem != location;
                elem = DOMHelper.getNextSiblingElement(elem))
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
                    CounterSignatureProperty.class))
            {
                digestInput.addNode(elem);
            } else if (isElementMatchingProperty(elem,
                    CompleteCertificateRefsProperty.class))
            {
                // there must be exactly one CompleteCertificateRefs element
                if (completeCertRefsPresent)
                    throw new CannotAddDataToDigestInputException(
                            new Exception(
                                    "Duplicate CompleteCertificateRefs property"
                                            + " in Signature"));
                completeCertRefsPresent = true;
                digestInput.addNode(elem);
                // TODO check if there are no CompleteCertificateRefs
                // *after* SigAndRefsTimeStamp
            } else if (isElementMatchingProperty(elem,
                    CompleteRevocationRefsProperty.class))
            {
                // there must be exactly one CompleteRevocationRefs element
                if (completeRevocRefsPresent)
                    throw new CannotAddDataToDigestInputException(
                            new Exception(
                                    "Duplicate CompleteRevocationRefs property"
                                            + " in Singature"));
                completeRevocRefsPresent = true;
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
            } else if (isElementMatchingProperty(elem,
                    CertificateValuesProperty.class))
            {
                if (certificateValuesPresent)
                    throw new CannotAddDataToDigestInputException(new Exception(
                            "Duplicate CertificateValues property in Signature"));

                certificateValuesPresent = true;
                digestInput.addNode(elem);
            } else if (isElementMatchingProperty(elem,
                    RevocationValuesProperty.class))
            {
                if (revocationValuesPresent)
                    throw new CannotAddDataToDigestInputException(new Exception(
                            "Duplicate RevocationValues property in Signature"));
                revocationValuesPresent = true;
                digestInput.addNode(elem);
            } else if (isElementMatchingProperty(elem,
                    SigAndRefsTimeStampProperty.class))
            {
                digestInput.addNode(elem);
            } else if (isElementMatchingProperty(elem,
                    AttrAuthoritiesCertValuesProperty.class))
            {
                digestInput.addNode(elem);
            } else if (isElementMatchingProperty(elem,
                    AttributeRevocationValuesProperty.class))
            {
                digestInput.addNode(elem);
            } else if (isElementMatchingProperty(elem,
                    ArchiveTimeStampProperty.class))
            {
                digestInput.addNode(elem);
            } // else: ignore other properties
            // TODO add TimeStampDataValidation property
        }

        if (certificateValuesPresent && revocationValuesPresent)
            return new ArchiveTimeStampProperty();
        else
            throw new CannotAddDataToDigestInputException(new Exception(
                    "Missing mandatory properties: CertificateValues"
                            + " or RevocationValues"));
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
