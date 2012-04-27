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

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * The context available during the verification of the qualifying properties.
 * @see QualifyingPropertyVerifier
 * @author Luís
 */
public class QualifyingPropertyVerificationContext
{
    private final XMLSignature signature;
    private final CertificationChainData certChainData;
    private final SignedObjectsData signedObjectsData;

    QualifyingPropertyVerificationContext(
            XMLSignature signature,
            CertificationChainData certChainData,
            SignedObjectsData signedObjectsData)
    {
        this.signature = signature;
        this.certChainData = certChainData;
        this.signedObjectsData = signedObjectsData;
    }

    public XMLSignature getSignature()
    {
        return signature;
    }

    public CertificationChainData getCertChainData()
    {
        return certChainData;
    }

    public SignedObjectsData getSignedObjectsData()
    {
        return signedObjectsData;
    }

    /**
     * 
     */
    public static class CertificationChainData
    {
        private final List<X509Certificate> certificateChain;
        private final Collection<X509CRL> crls;
        private final X500Principal validationCertIssuer;
        private final BigInteger validationCertSerialNumber;

        CertificationChainData(
                List<X509Certificate> certificateChain,
                Collection<X509CRL> crls,
                XMLX509IssuerSerial validationCertIssuerSerial)
        {
            this.certificateChain = Collections.unmodifiableList(certificateChain);
            this.crls = Collections.unmodifiableCollection(crls);
            if (validationCertIssuerSerial != null)
            {
                this.validationCertIssuer = new X500Principal(validationCertIssuerSerial.getIssuerName());
                this.validationCertSerialNumber = validationCertIssuerSerial.getSerialNumber();
            } else
            {
                validationCertIssuer = null;
                validationCertSerialNumber = null;
            }
        }

        public List<X509Certificate> getCertificateChain()
        {
            return certificateChain;
        }

        public Collection<X509CRL> getCrls()
        {
            return crls;
        }

        public X500Principal getValidationCertIssuer()
        {
            return validationCertIssuer;
        }

        public BigInteger getValidationCertSerialNumber()
        {
            return validationCertSerialNumber;
        }
    }

    /**
     * The find methods assume that object references are same-document references.
     * The references are resolved using the ResourceResolver of Apache XML Security,
     * which means the supported types of references (short-name XPointer, XPath)
     * depend on the configured resolvers. Fragments and short-name XPointers are
     * supported by the default configuration.
     */
    public static class SignedObjectsData
    {
        private final List<RawDataObjectDesc> dataObjs;
        private final Map<Element, RawDataObjectDesc> references;
        private final Map<Element, ObjectContainer> objects;
        private final Document signatureDoc;

        SignedObjectsData(
                List<RawDataObjectDesc> references,
                XMLSignature signature)
        {
            this.dataObjs = references;
            this.signatureDoc = signature.getDocument();

            // Map elements to References.
            this.references = new HashMap<Element, RawDataObjectDesc>(references.size());
            for (RawDataObjectDesc obj : references)
            {
                this.references.put(obj.getReference().getElement(), obj);
            }

            // Map elements to XMLObjects.
            int nXmlObjs = signature.getObjectLength();
            this.objects = new HashMap<Element, ObjectContainer>(nXmlObjs);
            for (int i = 0; i < nXmlObjs; i++)
            {
                ObjectContainer xmlObj = signature.getObjectItem(i);
                this.objects.put(xmlObj.getElement(), xmlObj);
            }
        }

        /**
         * In signature order.
         */
        public List<RawDataObjectDesc> getAllDataObjects()
        {
            return dataObjs;
        }

        public RawDataObjectDesc findSignedDataObject(String objReference)
        {
            return getReferencedElement(objReference, this.references);
        }

        public ObjectContainer findXMLObject(String objReference)
        {
            return getReferencedElement(objReference, this.objects);
        }

        private <TObj> TObj getReferencedElement(
                String objReference,
                Map<Element, TObj> mapper)
        {
            if (!objReference.startsWith("#"))
                throw new IllegalArgumentException();

            if (mapper.isEmpty())
                return null;

            // A little workaround to be able to use the ResourceResolver.
            Attr refAttr = this.signatureDoc.createAttributeNS(null, "ref");
            refAttr.setNodeValue(objReference);
            this.signatureDoc.createElementNS(null, "dummy").setAttributeNodeNS(refAttr);

            try
            {
                XMLSignatureInput refData = ResourceResolver.getInstance(refAttr, "").resolve(refAttr, "");
                // This has to be a NodeSet data because it is a same-document reference.
                Node refNode = refData.getSubNode();
                if (refNode.getNodeType() != Node.ELEMENT_NODE)
                    return null;
                // May return null.
                return mapper.get((Element)refNode);
            } catch (ResourceResolverException ex)
            {
                // Maybe an exception should be thrown...
                return null;
            }
        }
    }
}
