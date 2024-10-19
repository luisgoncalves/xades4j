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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.ElementProxy;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.XAdES4jXMLSigException;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.properties.QualifyingProperty;
import xades4j.utils.DOMHelper;

import static xades4j.utils.CanonicalizerUtils.allTransformsAreC14N;

/**
 *
 * @author Luís
 */
class SignatureUtils
{
    private SignatureUtils()
    {
    }

    static class ReferencesRes
    {
        /**
         * In signature order.
         */
        final List<RawDataObjectDesc> dataObjsReferences;
        final Reference signedPropsReference;

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

        List<RawDataObjectDesc> dataObjsReferences = new ArrayList<>(signedInfo.getLength() - 1);
        Reference signedPropsRef = null;

        for (int i = 0; i < signedInfo.getLength(); i++)
        {
            Reference ref = getReference(signedInfo, i);
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
            }
            else
            {
                RawDataObjectDesc dataObj = createDataObjectDesc(ref);
                dataObjsReferences.add(dataObj);
            }
        }

        if (null == signedPropsRef)
        {
            // TODO Still may be a XAdES signature, if the signing certificate is
            //  protected. For now, that scenario is not supported.
            throw new QualifyingPropertiesIncorporationException("SignedProperties reference not found");
        }

        return new ReferencesRes(dataObjsReferences, signedPropsRef);
    }

    private static Reference getReference(SignedInfo signedInfo, int i) throws XAdES4jXMLSigException
    {
        try
        {
            return signedInfo.item(i);
        } catch (XMLSecurityException ex)
        {
            throw new XAdES4jXMLSigException(String.format("Cannot process the %dth reference", i), ex);
        }
    }

    private static RawDataObjectDesc createDataObjectDesc(Reference ref) throws XAdES4jXMLSigException
    {
        RawDataObjectDesc dataObj = new RawDataObjectDesc(ref);
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
        return dataObj;
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
        Collection<Element> xadesElems = new ArrayList<>(1);

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
            Element referencedSignedPropsElem = getReferencedSignedPropsElem(signedPropsRef);
            if (referencedSignedPropsElem != signedPropsElem)
            {
                throw new QualifyingPropertiesIncorporationException("The referenced SignedProperties are not contained by the proper QualifyingProperties element");
            }
        } catch (XMLSignatureException ex)
        {
            throw new QualifyingPropertiesIncorporationException("Cannot get the referenced SignedProperties", ex);
        }
    }

    private static Element getReferencedSignedPropsElem(Reference signedPropsRef) throws XMLSignatureException, QualifyingPropertiesIncorporationException {
        Node sPropsNode = signedPropsRef.getNodesetBeforeFirstCanonicalization().getSubNode();
        if (sPropsNode == null || sPropsNode.getNodeType() != Node.ELEMENT_NODE)
        {
            throw new QualifyingPropertiesIncorporationException("The supposed reference over signed properties doesn't cover an element.");
        }

        // The referenced signed properties element must be the child of qualifying properties.
        return (Element) sPropsNode;
    }

    static boolean signatureReferencesElement(XMLSignature signature, ElementProxy elementProxy) throws XMLSecurityException
    {
        return signatureReferencesElement(signature, elementProxy.getElement());
    }

    static boolean signatureReferencesElement(XMLSignature signature, Element element) throws XMLSecurityException
    {
        SignedInfo si = signature.getSignedInfo();
        for (int i = 0; i < si.getLength(); i++)
        {
            Reference r = si.item(i);
            if (r.getContentsAfterTransformation().getSubNode() == element ||
                    r.getContentsBeforeTransformation().getSubNode() == element && allTransformsAreC14N(r))
            {
                return true;
            }
        }

        return false;
    }
}
