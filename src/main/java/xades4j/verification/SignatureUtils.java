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

import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.XAdES4jXMLSigException;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.properties.QualifyingProperty;
import xades4j.providers.CertificateValidationException;
import xades4j.utils.DOMHelper;

/**
 *
 * @author Luís
 */
class SignatureUtils
{

    private SignatureUtils()
    {
    }
    /**/

    static class KeyInfoRes
    {

        List<X509Certificate> keyInfoCerts;
        X509CertSelector certSelector;
        XMLX509IssuerSerial issuerSerial;

        KeyInfoRes(
                List<X509Certificate> keyInfoCerts,
                X509CertSelector certSelector,
                XMLX509IssuerSerial issuerSerial)
        {
            this.keyInfoCerts = keyInfoCerts;
            this.certSelector = certSelector;
            this.issuerSerial = issuerSerial;
        }
    }

    static KeyInfoRes processKeyInfo(
            KeyInfo keyInfo) throws CertificateValidationException
    {
        if (null == keyInfo || !keyInfo.containsX509Data())
        {
            throw new InvalidKeyInfoDataException("No X509Data to identify the leaf certificate");
        }

        List<X509Certificate> keyInfoCerts = new ArrayList<X509Certificate>(1);
        XMLX509IssuerSerial issuerSerial = null;

        // Certificate selector to select the leaf certificate. If ds:IssuerSerial
        // or ds:SubjectName are present, no order is needed in the certificates.
        // Otherwise, the first ds:X509Certificate is assumed as the signing certificate.
        X509CertSelector certSelector = new X509CertSelector();

        try
        {
            // The idea is to clearly identify the certificate that should be
            // used to validate the signature. If multiple X509Data are present
            // it gets ambiguous. I assumed that only ONE X509Data is present.
            X509Data x509Data = keyInfo.itemX509Data(0);

            // XML-DSIG 4.4.4: "elements that refer to a particular individual
            // certificate MUST be grouped inside a single X509Data element and
            // if the certificate to which they refer appears, it MUST also be in
            // that X509Data element".
            // "All certificates appearing in an X509Data element MUST relate to
            // the validation key by either containing it or being part of a
            // certification chain that terminates in a certificate containing
            // the validation key".

            if (x509Data.containsIssuerSerial())
            {
                issuerSerial = x509Data.itemIssuerSerial(0);
                certSelector.setIssuer(new X500Principal(issuerSerial.getIssuerName()));
                certSelector.setSerialNumber(issuerSerial.getSerialNumber());
            } else if (x509Data.containsSubjectName())
            {
                certSelector.setSubject(new X500Principal(x509Data.itemSubjectName(0).getSubjectName()));
            } else if (x509Data.containsCertificate())
            {
                certSelector.setCertificate(x509Data.itemCertificate(0).getX509Certificate());
            } else
            // No criteria to select the leaf certificate.
            // Improvement: search the SigningCertiticate property and try to
            // find the "bottom" certificate.
            {
                throw new InvalidKeyInfoDataException("No criteria to select the leaf certificate");
            }

            // Even if certificates are not used as selection criteria, they have
            // to be collected because they may be needed to build the cert path.
            if (x509Data.containsCertificate())
            {
                for (int j = 0; j < x509Data.lengthCertificate(); ++j)
                {
                    keyInfoCerts.add(x509Data.itemCertificate(j).getX509Certificate());
                }
            }
        } catch (XMLSecurityException ex)
        {
            throw new InvalidKeyInfoDataException("Cannot process X509Data", ex);
        }

        return new KeyInfoRes(keyInfoCerts, certSelector, issuerSerial);
    }

    /**************************************************************************/
    static class ReferencesRes
    {

        /**
         * In signature order.
         */
        List<RawDataObjectDesc> dataObjsReferences;
        Reference signedPropsReference;

        ReferencesRes(
                List<RawDataObjectDesc> dataObjsReferences,
                Reference signedPropsReference)
        {
            this.dataObjsReferences = Collections.unmodifiableList(dataObjsReferences);
            this.signedPropsReference = signedPropsReference;
        }
    }

    static ReferencesRes processReferences(
            XMLSignature signature) throws QualifyingPropertiesIncorporationException, XAdES4jXMLSigException
    {
        SignedInfo signedInfo = signature.getSignedInfo();

        List<RawDataObjectDesc> dataObjsReferences = new ArrayList<RawDataObjectDesc>(signedInfo.getLength() - 1);
        Reference signedPropsRef = null;

        for (int i = 0; i < signedInfo.getLength(); i++)
        {
            Reference ref;
            try
            {
                ref = signedInfo.item(i);
            } catch (XMLSecurityException ex)
            {
                throw new XAdES4jXMLSigException(String.format("Cannot process the %dth reference", i), ex);
            }

            String refTypeUri = ref.getType();

            // XAdES 6.3.1: "In order to protect the properties with the signature,
            // a ds:Reference element MUST be added to the XMLDSIG signature (...)
            // composed in such a way that it uses the SignedProperties element (...)
            // as the input for computing its corresponding digest. Additionally,
            // (...) use the Type attribute of this particular ds:Reference element,
            // with its value set to: http://uri.etsi.org/01903#SignedProperties."
            if (QualifyingProperty.SIGNED_PROPS_TYPE_URI.equals(refTypeUri))
            {
                if (signedPropsRef != null)
                {
                    throw new QualifyingPropertiesIncorporationException("Multiple references to SignedProperties");
                }
                signedPropsRef = ref;
            } else
            {
                RawDataObjectDesc dataObj = new RawDataObjectDesc(ref);
                dataObjsReferences.add(dataObj);
                try
                {
                    Transforms transfs = ref.getTransforms();
                    if (transfs != null)
                    {
                        for (int j = 0; j < transfs.getLength(); ++j)
                        {
                            dataObj.withTransform(new GenericAlgorithm(transfs.item(j).getURI()));
                        }
                    }
                } catch (XMLSecurityException ex)
                {
                    throw new XAdES4jXMLSigException("Cannot process transfroms", ex);
                }

            }
        }

        if (null == signedPropsRef)
        // !!!
        // Still may be a XAdES signature, if the signing certificate is
        // protected. For now, that scenario is not suported.
        {
            throw new QualifyingPropertiesIncorporationException("SignedProperties reference not found");
        }

        return new ReferencesRes(dataObjsReferences, signedPropsRef);
    }

    /***************************************************************************/
    static Element getQualifyingPropertiesElement(XMLSignature signature) throws QualifyingPropertiesIncorporationException
    {
        boolean foundXAdESContainerObject = false;
        Element qualifyingPropsElem = null;

        for (int i = 0; i < signature.getObjectLength(); ++i)
        {
            Element objElem = signature.getObjectItem(i).getElement();
            Collection<Element> xadesElems = getXAdESChildElements(objElem);

            if (!xadesElems.isEmpty())
            {
                // XAdES 6.3: "all instances of the QualifyingProperties and the
                // QualifyingPropertiesReference elements MUST occur within a single
                // ds:Object element". This could be tested with qualifyingPropsNode
                // because I'm only supporting QualifyingProperties. Anyway, the
                // exception message is more specific this way.
                if (foundXAdESContainerObject)
                {
                    throw new QualifyingPropertiesIncorporationException("All instances of the QualifyingProperties element must occur within a single ds:Object element");
                }

                // If this Object had XAdES elements, it is "the Object". The for
                // cycle over the Objects is not interrupted because I need to
                // check the correct incorporation of properties (XAdES G.2.2.1).
                foundXAdESContainerObject = true;

                for (Element e : xadesElems)
                {
                    if (e.getLocalName().equals(QualifyingProperty.QUALIFYING_PROPS_TAG))
                    {
                        // XAdES 6.3: "at most one instance of the QualifyingProperties
                        // element MAY occur within this ds:Object element".
                        if (qualifyingPropsElem != null)
                        {
                            throw new QualifyingPropertiesIncorporationException("Only a single QualifyingProperties element is allowed inside the ds:Object element");
                        }
                        qualifyingPropsElem = e;

                    } else
                    // QualifyingPropertiesReference is not supported, so
                    // nothing else on this namespace should appear.
                    {
                        throw new QualifyingPropertiesIncorporationException("Only the QualifyingProperties element is supported");
                    }
                }
            }
        }

        if (!foundXAdESContainerObject)
        {
            throw new QualifyingPropertiesIncorporationException("Couldn't find any XAdES elements");
        }

        return qualifyingPropsElem;
    }

    private static Collection<Element> getXAdESChildElements(
            Element xmlObjectElem)
    {
        Collection<Element> xadesElems = new ArrayList<Element>(1);

        Node child = xmlObjectElem.getFirstChild();
        while (child != null)
        {
            if (child.getNodeType() == Node.ELEMENT_NODE && QualifyingProperty.XADES_XMLNS.equals(child.getNamespaceURI()))
            {
                xadesElems.add((Element) child);
            }
            child = child.getNextSibling();
        }

        return xadesElems;
    }

    static void checkSignedPropertiesIncorporation(Element qualifyingPropsElem, Reference signedPropsRef) throws QualifyingPropertiesIncorporationException
    {
        Element signedPropsElem = DOMHelper.getFirstChildElement(qualifyingPropsElem);
        if (signedPropsElem == null
                || !signedPropsElem.getLocalName().equals(QualifyingProperty.SIGNED_PROPS_TAG)
                || !signedPropsElem.getNamespaceURI().equals(QualifyingProperty.XADES_XMLNS))
        {
            throw new QualifyingPropertiesIncorporationException("SignedProperties not found as the first child of QualifyingProperties.");
        }

        DOMHelper.useIdAsXmlId(signedPropsElem);

        // Only QualifyingProperties in the signature's document are supported.
        // XML-DSIG 4.3.3.2: "a same-document reference is defined as a URI-Reference
        // that consists of a hash sign ('#') followed by a fragment"
        if (!signedPropsRef.getURI().startsWith("#"))
        {
            throw new QualifyingPropertiesIncorporationException("Only QualifyingProperties in the signature's document are supported");
        }

        try
        {
            Node sPropsNode = signedPropsRef.getNodesetBeforeFirstCanonicalization().getSubNode();
            if (sPropsNode == null || sPropsNode.getNodeType() != Node.ELEMENT_NODE)
            {
                throw new QualifyingPropertiesIncorporationException("The supposed reference over signed properties doesn't cover an element.");
            }

            // The referenced signed properties element must be the child of qualifying properties.
            Element referencedSignedPropsElem = (Element) sPropsNode;
            if (referencedSignedPropsElem != signedPropsElem)
            {
                throw new QualifyingPropertiesIncorporationException("The referenced SignedProperties are not contained by the proper QualifyingProperties element");
            }
        } catch (XMLSignatureException ex)
        {
            throw new QualifyingPropertiesIncorporationException("Cannot get the referenced SignedProperties", ex);
        }
    }
}
