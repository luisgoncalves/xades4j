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
package xades4j.verification;

import com.google.inject.Inject;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.XAdES4jException;
import xades4j.XAdES4jXMLSigException;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.UnsignedProperties;
import xades4j.production.XadesSignatureFormatExtender;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.ValidationData;
import xades4j.utils.ObjectUtils;
import xades4j.utils.PropertiesUtils;
import xades4j.verification.SignatureUtils.KeyInfoRes;
import xades4j.verification.SignatureUtils.ReferencesRes;
import xades4j.xml.unmarshalling.QualifyingPropertiesUnmarshaller;
import xades4j.xml.unmarshalling.UnmarshalException;

/**
 *
 * @author Luís
 */
class XadesVerifierImpl implements XadesVerifier
{
    static
    {
        org.apache.xml.security.Init.init();
    }
    /**/
    private final CertificateValidationProvider certificateValidator;
    private final QualifyingPropertiesVerifier qualifyingPropertiesVerifier;
    private final QualifyingPropertiesUnmarshaller qualifPropsUnmarshaller;
    private final Collection<CustomSignatureVerifier> customSigVerifiers;

    @Inject
    protected XadesVerifierImpl(
            CertificateValidationProvider certificateValidator,
            QualifyingPropertiesVerifier qualifyingPropertiesVerifier,
            QualifyingPropertiesUnmarshaller qualifPropsUnmarshaller,
            Collection<CustomSignatureVerifier> customSigVerifiers)
    {
        if (ObjectUtils.anyNull(
                certificateValidator, qualifPropsUnmarshaller, customSigVerifiers))
            throw new NullPointerException("One or more arguments are null");

        this.certificateValidator = certificateValidator;
        this.qualifyingPropertiesVerifier = qualifyingPropertiesVerifier;
        this.qualifPropsUnmarshaller = qualifPropsUnmarshaller;
        this.customSigVerifiers = customSigVerifiers;
        this.customSigVerifiers.add(new TimeStampCoherenceVerifier());
    }

    void setAcceptUnknownProperties(boolean accept)
    {
        this.qualifPropsUnmarshaller.setAcceptUnknownProperties(accept);
    }

    @Override
    public XAdESVerificationResult verify(Element signatureElem) throws XAdES4jException
    {
        if (null == signatureElem)
            throw new NullPointerException("Signature node not specified");

        XMLSignature signature;
        try
        {
            signature = new XMLSignature(signatureElem, "");
        } catch (XMLSignatureException ex)
        {
            throw new UnmarshalException("Bad XML Signature format", ex);
        } catch (XMLSecurityException ex)
        {
            throw new UnmarshalException(ex.getMessage(), ex.getOriginalException());
        }

        String signatureId = signature.getId();
        if (null == signatureId)
            throw new UnmarshalException("XML signature doesn't have an Id");

        /* References */

        ReferencesRes referencesRes = SignatureUtils.processReferences(signature);

        /* Get and check the QualifyingProperties element */

        // Get the referenced SignedProperties
        Node signedPropsNode = getSignedPropertiesNode(referencesRes.signedPropsReference);
        // Get the supposed final QualifyingProperties node.
        Node signedPropsNodeParent = signedPropsNode.getParentNode();
        // Get the QualifyingProperties node from whithin a ds:Object (and check
        // correct incorporation).
        Element qualifyingPropsElem = SignatureUtils.getQualifyingPropertiesElement(signature);
        // Check if the parent of the referenced SignedProperties element is the
        // QualifyingProperties element found inside ds:Object.
        if (signedPropsNodeParent != qualifyingPropsElem)
            throw new QualifyingPropertiesIncorporationException("The referenced SignedProperties are not contained by the proper QualifyingProperties element");

        // Check the QualifyingProperties 'Target' attribute.
        Node targetAttr = qualifyingPropsElem.getAttributeNodeNS(null, QualifyingProperty.TARGET_ATTR);
        if (null == targetAttr)
        {
            targetAttr = qualifyingPropsElem.getAttributeNodeNS(QualifyingProperty.XADES_XMLNS, QualifyingProperty.TARGET_ATTR);
            if (null == targetAttr)
                throw new QualifyingPropertiesIncorporationException("QualifyingProperties Target attribute not present");
        }
        String targetValue = targetAttr.getNodeValue();
        if (null == targetValue ||
                !targetValue.startsWith("#") ||
                !targetValue.substring(1).equals(signatureId))
            throw new QualifyingPropertiesIncorporationException("QualifyingProperties target doesn't match the signature's Id");

        /* Certification path */

        KeyInfoRes keyInfoRes = SignatureUtils.processKeyInfo(signature.getKeyInfo());
        ValidationData certValidationRes = this.certificateValidator.validate(keyInfoRes.certSelector, keyInfoRes.keyInfoCerts);
        if (null == certValidationRes)
            throw new NullPointerException("Certificate validator returned null data");
        X509Certificate validationCert = certValidationRes.getCerts().get(0);

        /* Core signature verification */

        boolean status;
        try
        {
            status = signature.checkSignatureValue(validationCert);
        } catch (XMLSignatureException ex)
        {
            throw new XAdES4jXMLSigException("Cannot verify the signature: " + ex.getMessage(), ex);
        }

        if (!status)
            try
            {
                // Check if it is a failure due to the signature value or references
                // validation.
                status = signature.getSignedInfo().verifyReferences();

                if (status)
                    // References are OK; this is a problem on the signature value
                    // itself.
                    throw new SignatureValueException(signature);
                else
                {
                    // References are not OK; get the first invalid Reference.
                    SignedInfo si = signature.getSignedInfo();
                    for (int i = 0; i < si.getLength(); i++)
                    {
                        Reference r = si.item(i);
                        if (!r.verify())
                            throw new ReferenceValueException(signature, r);
                    }
                }
            } catch (XMLSecurityException ex)
            {
                throw new XAdES4jXMLSigException("Cannot verify the references", ex);
            }

        /* Umarshal the qualifying properties */

        QualifPropsDataCollectorImpl propsDataCollector = new QualifPropsDataCollectorImpl();
        qualifPropsUnmarshaller.unmarshalProperties(qualifyingPropsElem, propsDataCollector);

        /* Verify the qualifying properties */

        Collection<PropertyDataObject> qualifPropsData = propsDataCollector.getPropertiesData();
        // Create the verification context.
        QualifyingPropertyVerificationContext ctx = new QualifyingPropertyVerificationContext(
                signature,
                new QualifyingPropertyVerificationContext.CertificationChainData(
                certValidationRes.getCerts(),
                certValidationRes.getCrls(),
                keyInfoRes.issuerSerial),
                /**/
                new QualifyingPropertyVerificationContext.SignedObjectsData(
                referencesRes.dataObjsReferences,
                signature));
        // Verify the properties. Data structure verification is included.
        Collection<PropertyInfo> props = this.qualifyingPropertiesVerifier.verifyProperties(qualifPropsData, ctx);

        XAdESVerificationResult res = new XAdESVerificationResult(
                XAdESFormChecker.checkForm(props),
                signature,
                certValidationRes,
                props,
                referencesRes.dataObjsReferences);

        // Apply the custom signature verifiers.
        for (CustomSignatureVerifier customVer : this.customSigVerifiers)
        {
            customVer.verify(res, ctx);
        }

        return res;
    }

    /*************************************************************************************/
    /**/
    private static Node getSignedPropertiesNode(Reference signedPropsRef) throws QualifyingPropertiesIncorporationException
    {
        // Only QualifyingProperties in the signature's document are supported.
        // XML-DSIG 4.3.3.2: "a same-document reference is defined as a URI-Reference
        // that consists of a hash sign ('#') followed by a fragment"
        if (!signedPropsRef.getURI().startsWith("#"))
            throw new QualifyingPropertiesIncorporationException("Only QualifyingProperties in the signature's document are supported");

        String msg = "Cannot get the SignedProperties element";
        try
        {
            Node sPropsNode = signedPropsRef.getNodesetBeforeFirstCanonicalization().getSubNode();
            if (sPropsNode != null)
                if (sPropsNode.getNodeType() != Node.ELEMENT_NODE ||
                        !sPropsNode.getLocalName().equals(QualifyingProperty.SIGNED_PROPS_TAG) ||
                        !sPropsNode.getNamespaceURI().equals(QualifyingProperty.XADES_XMLNS))
                    throw new QualifyingPropertiesIncorporationException("The supposed reference over signed properties doesn't cover a XAdES SignedProperties element.");
                else
                    return sPropsNode;
        } catch (XMLSignatureException ex)
        {
            msg = msg + ": " + ex.getMessage();
        }
        throw new QualifyingPropertiesIncorporationException(msg);
    }

    /*************************************************************************************/
    @Override
    public XAdESVerificationResult verify(
            Element signatureElem,
            XadesSignatureFormatExtender formatExtender,
            XAdESForm finalForm) throws XAdES4jException
    {
        if (null == finalForm || null == formatExtender)
            throw new NullPointerException("Parameters cannot be null");

        if (finalForm.before(XAdESForm.T) || finalForm.after(XAdESForm.X_L))
            throw new IllegalArgumentException("Signature format can only be extended to XAdES-T, C, X or X-L");

        XAdESVerificationResult res = this.verify(signatureElem);
        XAdESForm actualForm = res.getSignatureForm();

        if (actualForm.before(finalForm))
        {
            if (finalForm.after(XAdESForm.C))
                // XAdES-X, X-L or A.
                //
                if (finalForm.before(XAdESForm.A))
                {
                    // XAdES-X or X-L
                    if (actualForm != XAdESForm.C)
                        throw new IllegalArgumentException("XAdES-C is required to extend to XAdES-X or X-L");
                } else if (actualForm != XAdESForm.X_L)
                    // XAdES-A
                    throw new IllegalArgumentException("XAdES-X-L is required to extend to XAdES-A");


            // Valid form transitions:
            // * BES/EPES -> T
            // * BES/EPES -> C
            // * T -> C
            // * C -> X
            // * C -> X-L
            // * X -> X-L (not supported with the libray defaults: X cannot be verified)
            // * X-L -> A (not supported with the libray defaults: X-L cannot be verified)

            Collection<UnsignedSignatureProperty> usp = new ArrayList<UnsignedSignatureProperty>(3);

            switch (finalForm)
            {
                case C:
                    PropertiesUtils.addXadesCProperties(usp, res.getValidationData());
                    if (actualForm == XAdESForm.T)
                        break;
                case T:
                    PropertiesUtils.addXadesTProperties(usp);
                    break;
                case X_L:
                    PropertiesUtils.addXadesXLProperties(usp, res.getValidationData());
                    if (actualForm == XAdESForm.X)
                        break;
                case X:
                    PropertiesUtils.addXadesXProperties(usp);
                    break;
                case A:
                    PropertiesUtils.addXadesAProperties(usp);
            }

            formatExtender.enrichSignature(res.getXmlSignature(), new UnsignedProperties(usp));
        }
        return res;
    }
}
