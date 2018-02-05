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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

import xades4j.providers.ValidationData;
import xades4j.verification.SignatureUtils.KeyInfoRes;

/**
 * The context available during the verification of the qualifying properties.
 * @see QualifyingPropertyVerifier
 * @author Luís
 */
public class QualifyingPropertyVerificationContext
{
    private final XMLSignature signature;
    private CertificationChainData certChainData;
    private final SignedObjectsData signedObjectsData;
    private final KeyInfoRes keyInfoRes;
    // validation data collected during verification of attributes (trusted)
    private Collection<ValidationData> attributeValidationData;
    // validation data collected during verification of signature (trusted)
    private Collection<ValidationData> signatureValidationData;
    private final Set<X509Certificate> untrustedAttributeCertificates;
    private final Set<X509CRL> untrustedAttributeCRLs;
    private final Set<X509Certificate> untrustedSignatureCertificates;
    private final Set<X509CRL> untrustedSignatureCRLs;

    private Date currentTime;

    QualifyingPropertyVerificationContext(
            XMLSignature signature,
            CertificationChainData certChainData,
            SignedObjectsData signedObjectsData,
            Date currentTime)
    {
        this.signature = signature;
        this.certChainData = certChainData;
        this.signedObjectsData = signedObjectsData;
        attributeValidationData = new ArrayList<ValidationData>();
        signatureValidationData = new ArrayList<ValidationData>();
        this.keyInfoRes = null;
        this.currentTime = currentTime;
        untrustedAttributeCertificates = new HashSet<X509Certificate>();
        untrustedAttributeCRLs = new HashSet<X509CRL>();
        untrustedSignatureCertificates = new HashSet<X509Certificate>();
        untrustedSignatureCRLs = new HashSet<X509CRL>();
    }

    public QualifyingPropertyVerificationContext(
            XMLSignature signature,
            KeyInfoRes keyInfoRes,
            SignedObjectsData signedObjectsData,
            Date currentTime)
    {
        this.signature = signature;
        this.signedObjectsData = signedObjectsData;
        this.certChainData = null;
        this.keyInfoRes = keyInfoRes;
        attributeValidationData = new ArrayList<ValidationData>();
        signatureValidationData = new ArrayList<ValidationData>();
        this.currentTime = currentTime;
        untrustedAttributeCertificates = new HashSet<X509Certificate>();
        untrustedAttributeCRLs = new HashSet<X509CRL>();
        untrustedSignatureCertificates = new HashSet<X509Certificate>();
        untrustedSignatureCRLs = new HashSet<X509CRL>();
    }

    public Collection<ValidationData> getAttributeValidationData()
    {
        return attributeValidationData;
    }

    public void addAttributeValidationData(ValidationData validationData)
    {
        attributeValidationData.add(validationData);
    }

    public Collection<ValidationData> getSignatureValidationData()
    {
        return signatureValidationData;
    }

    public void addSignatureValidationData(ValidationData validationData)
    {
        signatureValidationData.add(validationData);
    }

    /**
     * Changes the time at which subsequent verifications take place, used to ensure
     * monotonicity of time in time stamps.
     *
     * @param currentTime new time at which subsequent verifications should happen
     * @throws IllegalArgumentException when currentTime is <b>later</b> (in future)
     * than time saved in this context
     * ({@code currentTime.getTime() > this.currentTime.getTime()})
     */
    public void setCurrentTime(Date currentTime)
    throws IllegalArgumentException
    {
        if (this.currentTime.getTime() < currentTime.getTime()) {
            final SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
            throw new IllegalArgumentException(String.format("New time from TimeStamp is in the future %s < %s",
                    formatter.format(this.currentTime.getTime()), formatter.format(currentTime.getTime())));
        }

        this.currentTime = new Date(currentTime.getTime());
    }

    public Date getCurrentTime()
    {
        return currentTime;
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

    public KeyInfoRes getKeyInfoRes()
    {
        return keyInfoRes;
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
                XMLSignatureInput refData = ResourceResolver.getInstance(refAttr, "", true).resolve(refAttr, "", true);
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

    public void setCertificationChainData(
            CertificationChainData certificationChainData)
    {
        this.certChainData = certificationChainData;
    }

    /**
     * Remember the untrusted certificates found in properties.
     * The same certificate can be provided multiple times and it will be saved only once.
     * @param certificates found properties
     */
    public void addAttributeCertificates(Collection<X509Certificate> certificates)
    {
        untrustedAttributeCertificates.addAll(certificates);
    }

    /**
     * Remember the untrusted attribute certificates found in properties.
     * The same CRL can be provided multiple times and it will be saved only once.
     * @param crls found crls
     */
    public void addAttributeCRLs(Collection<X509CRL> crls)
    {
        untrustedAttributeCRLs.addAll(crls);
    }

    /**
     * @return list of untrusted CRLs read from properties
     */
    public Collection<X509CRL> getAttributeCRLs()
    {
        return untrustedAttributeCRLs;
    }

    /**
     * @return list of untrusted certificates read from properties
     */
    public Collection<X509Certificate> getAttributeCertificates()
    {
        return untrustedAttributeCertificates;
    }

    /**
     * Remember the untrusted signature certificates found in properties.
     * The same certificates can be provided multiple times and it will be saved only
     * once.
     * @param certificates certificates to save
     */
    public void addSignatureCertificates(Collection<X509Certificate> certificates)
    {
        untrustedSignatureCertificates.addAll(certificates);
    }

    /**
     * Remember the untrusted signature revocation data (CRLs) found in properties.
     * The same CRL can be provided multiple times and it will be save only one.
     * @param crls CRLs to save
     */
    public void addSignatureCRLs(Collection<X509CRL> crls)
    {
        untrustedSignatureCRLs.addAll(crls);
    }

    public Collection<X509CRL> getSignatureCRLs()
    {
        return untrustedSignatureCRLs;
    }

    public Collection<X509Certificate> getSignatureCertificates()
    {
        return untrustedSignatureCertificates;
    }
}
