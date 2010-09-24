/*
 *  XAdES4j - A Java library for generation and verification of XAdES signatures.
 *  Copyright (C) 2010 Luis Goncalves.
 * 
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation; either version 2 of the License, or any later version.
 * 
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 *  Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.production;

import xades4j.properties.QualifyingProperties;
import xades4j.properties.DataObjectDesc;
import com.google.inject.Inject;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.SigningCertificateProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.UnsupportedAlgorithmException;
import xades4j.XAdES4jException;
import xades4j.XAdES4jXMLSigException;
import xades4j.properties.data.SigAndDataObjsPropertiesData;
import xades4j.providers.AlgorithmsProvider;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.utils.DOMHelper;
import xades4j.utils.ObjectUtils;
import xades4j.xml.marshalling.SignedPropertiesMarshaller;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;

/**
 * Base logic for producing XAdES signatures (XAdES-BES).
 * @author Luís
 */
class SignerBES implements XadesSigner
{
    static
    {
        Init.initXMLSec();
    }
    /**/
    private final AlgorithmsProvider algorithmsProvider;
    private final KeyingDataProvider keyingProvider;
    private final PropertiesDataObjectsGenerator propsDataObjectsGenerator;
    private final SignedPropertiesMarshaller signedPropsMarshaller;
    private final UnsignedPropertiesMarshaller unsignedPropsMarshaller;
    /**/
    private final QualifyingPropertiesProcessor qualifPropsProcessor;

    @Inject
    protected SignerBES(
            KeyingDataProvider keyingProvider,
            SignaturePropertiesProvider signaturePropsProvider,
            DataObjectPropertiesProvider dataObjPropsProvider,
            PropertiesDataObjectsGenerator propsDataObjectsGenerator,
            AlgorithmsProvider algorithmsProvider,
            SignedPropertiesMarshaller signedPropsMarshaller,
            UnsignedPropertiesMarshaller unsignedPropsMarshaller)
    {
        if (ObjectUtils.anyNull(
                keyingProvider, signaturePropsProvider, dataObjPropsProvider, propsDataObjectsGenerator,
                algorithmsProvider, signedPropsMarshaller, unsignedPropsMarshaller))
            throw new NullPointerException("One or more arguments are null");

        this.algorithmsProvider = algorithmsProvider;
        this.keyingProvider = keyingProvider;
        this.propsDataObjectsGenerator = propsDataObjectsGenerator;
        this.signedPropsMarshaller = signedPropsMarshaller;
        this.unsignedPropsMarshaller = unsignedPropsMarshaller;

        this.qualifPropsProcessor = new QualifyingPropertiesProcessor(signaturePropsProvider, dataObjPropsProvider);
    }

    @Override
    public final XadesSignatureResult sign(
            SignedDataObjects signedDataObjects,
            Node parent) throws XAdES4jException
    {
        if (null == parent)
            throw new NullPointerException("Parent node cannot be null");
        if (null == signedDataObjects)
            throw new NullPointerException("References cannot be null");
        if (signedDataObjects.isEmpty())
            throw new IllegalArgumentException("Data objects list is empty");

        // Generate unique identifiers for the Signature and the SignedProperties.
        String signatureId = String.format("xmldsig-%s", UUID.randomUUID());
        String signedPropsId = String.format("%s-signedprops", signatureId);

        // Signing certificate chain (may contain only the signing certificate).
        List<X509Certificate> signingCertificateChain = this.keyingProvider.getSigningCertificateChain();
        if (null == signingCertificateChain || signingCertificateChain.isEmpty())
            throw new SigningCertChainException("Signing certificate not provided");
        X509Certificate signingCertificate = signingCertificateChain.get(0);

        // Get the specific signature algorithm for the key's algorithm.
        String sigAlgUri = algorithmsProvider.getSignatureAlgorithm(signingCertificate.getPublicKey().getAlgorithm());
        if (null == sigAlgUri)
            throw new NullPointerException("Signature algorithm URI not provided");

        String canonAlgUri = algorithmsProvider.getCanonicalizationAlgorithmForSignature();
        if (null == canonAlgUri)
            throw new NullPointerException("Canonicalization algorithm URI not provided");

        String digestAlgUri = algorithmsProvider.getDigestAlgorithmForDataObjsReferences();
        if (null == digestAlgUri)
            throw new NullPointerException("Digest algorithm URI not provided");

        // The XMLSignature (ds:Signature).
        XMLSignature signature = null;
        try
        {
            signature = new XMLSignature(DOMHelper.getOwnerDocument(parent), "", sigAlgUri, canonAlgUri);
            signature.setId(signatureId);
        } catch (XMLSecurityException ex)
        {
            // Following the code, doesn't seem to be thrown at all.
            throw new XAdES4jXMLSigException(ex.getMessage());
        }

        /* References */
        // Process the data object informations to get the References and mappings.
        // After this call all the signed data objects References and XMLObjects
        // are added to the signature.
        Map<DataObjectDesc, Reference> referenceMappings = DataObjectDescsProcessor.process(
                signedDataObjects.getDataObjectsDescs(),
                signature,
                digestAlgUri);

        /* SignedProperties reference */
        // XAdES 6.3.1: "In order to protect the properties with the signature,
        // a ds:Reference element MUST be added to the XMLDSIG signature (...)
        // composed in such a way that it uses the SignedProperties element (...)
        // as the input for computing its corresponding digest. Additionally,
        // (...) use the Type attribute of this particular ds:Reference element,
        // with its value set to: http://uri.etsi.org/01903#SignedProperties."
        try
        {
            signature.addDocument('#' + signedPropsId, null, digestAlgUri, null, QualifyingProperty.SIGNED_PROPS_TYPE_URI);
        } catch (XMLSignatureException ex)
        {
            // Seems to be thrown when the digest algorithm is not supported. In
            // this case, if it wasn't thrown when processing the data objects it
            // shouldn't be thrown now!
            throw new UnsupportedAlgorithmException(
                    "Digest algorithm not supported in the XML Signature provider: " + ex.getMessage(),
                    digestAlgUri);
        }

        /* QualifyingProperties element */
        // Create the QualifyingProperties element
        Element qualifyingPropsElem = ElementProxy.createElementForFamily(
                signature.getDocument(),
                QualifyingProperty.XADES_XMLNS, QualifyingProperty.QUALIFYING_PROPS_TAG);
        qualifyingPropsElem.setAttributeNS(null, QualifyingProperty.TARGET_ATTR, '#' + signatureId);
        qualifyingPropsElem.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xades141", QualifyingProperty.XADESV141_XMLNS);
        // ds:Object to contain QualifyingProperties
        ObjectContainer qPropsXmlObj = new ObjectContainer(signature.getDocument());
        qPropsXmlObj.appendChild(qualifyingPropsElem);
        try
        {
            signature.appendObject(qPropsXmlObj);
        } catch (XMLSignatureException ex)
        {
            // -> xmlSignature.appendObject(xmlObj): not thrown when signing.
            throw new IllegalStateException(ex);
        }

        /* Collect the properties */
        // Get the format specific signature properties.
        Collection<SignedSignatureProperty> fsssp = new ArrayList<SignedSignatureProperty>(2);
        Collection<UnsignedSignatureProperty> fsusp = new ArrayList<UnsignedSignatureProperty>(2);
        getFormatSpecificSignatureProperties(fsssp, fsusp, signingCertificateChain);
        // Gather all the signature and data objects properties.
        QualifyingProperties qualifProps = qualifPropsProcessor.getQualifyingProperties(
                signedDataObjects, fsssp, fsusp);

        /* Marshal the signed properties */
        // Create the context for signed properties data objects generation.
        PropertiesDataGenerationContext propsDataGenCtx = new PropertiesDataGenerationContext(
                signedDataObjects.getDataObjectsDescs(),
                referenceMappings,
                parent,
                algorithmsProvider);
        // Generate the signed properties data objects. The data objects structure
        // is verifier in the process.
        SigAndDataObjsPropertiesData signedPropsData = this.propsDataObjectsGenerator.generateSignedPropertiesData(
                qualifProps.getSignedProperties(),
                propsDataGenCtx);
        // Marshal the signed properties data to the QualifyingProperties node.
        this.signedPropsMarshaller.marshal(
                signedPropsData,
                signedPropsId,
                qualifyingPropsElem);

        /* ds:KeyInfo */
        buildKeyInfo(signingCertificate, signature);

        /* Apply the signature */
        PrivateKey signingKey = keyingProvider.getSigningKey(signingCertificate);
        try
        {
            parent.appendChild(signature.getElement());
            try
            {

                signature.sign(signingKey);
            } catch (XMLSignatureException ex)
            {

                throw new XAdES4jXMLSigException(ex.getMessage(), ex);
            }
            // Set the ds:SignatureValue id.
            Element sigValueElem = DOMHelper.getFirstDescendant(
                    signature.getElement(),
                    Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);
            sigValueElem.setAttributeNS(
                    null, Constants._ATT_ID,
                    String.format("%s-sigvalue", signatureId));

            /* Marshal unsigned properties */
            // Generate the unsigned properties data objects. The data objects structure
            // is verifier in the process.
            propsDataGenCtx.setTargetXmlSignature(signature);
            SigAndDataObjsPropertiesData unsignedPropsData = this.propsDataObjectsGenerator.generateUnsignedPropertiesData(
                    qualifProps.getUnsignedProperties(),
                    propsDataGenCtx);
            // Marshal the unsigned properties to the final QualifyingProperties node.
            this.unsignedPropsMarshaller.marshal(
                    unsignedPropsData,
                    String.format("%s-unsignedprops", signatureId),
                    qualifyingPropsElem);
        } catch (XAdES4jException ex)
        {
            parent.removeChild(signature.getElement());
            throw ex;
        }

        return new XadesSignatureResult(signature, qualifProps);
    }

    private static void buildKeyInfo(
            X509Certificate signingCertificate,
            XMLSignature xmlSig) throws KeyingDataException
    {
        // Check key usage. KeyUsage[0] = digitalSignature.
        boolean[] keyUsage = signingCertificate.getKeyUsage();
        if (keyUsage != null && keyUsage[0] == false)
            throw new SigningCertKeyUsageException(signingCertificate);

        try
        {
            // Check certifcate validity period.
            signingCertificate.checkValidity();
        } catch (CertificateException ce)
        {
            // CertificateExpiredException or CertificateNotYetValidException
            throw new SigningCertValidityException(signingCertificate);
        }

        X509Data x509Data = new X509Data(xmlSig.getDocument());
        x509Data.addSubjectName(signingCertificate.getSubjectX500Principal().getName());
        x509Data.addIssuerSerial(
                signingCertificate.getIssuerX500Principal().getName(),
                signingCertificate.getSerialNumber());
        try
        {
            x509Data.addCertificate(signingCertificate);

        } catch (XMLSecurityException ex)
        {
            throw new KeyingDataException(ex.getMessage(), ex);
        }

        xmlSig.getKeyInfo().add(x509Data);
        xmlSig.addKeyInfo(signingCertificate.getPublicKey());
    }

    /**
     * Override in subclasses to collect the signature properties that are mandatory
     * in the corresponding format.
     */
    protected void getFormatSpecificSignatureProperties(
            Collection<SignedSignatureProperty> formatSpecificSignedSigProps,
            Collection<UnsignedSignatureProperty> formatSpecificUnsignedSigProps,
            List<X509Certificate> signingCertificateChain) throws XAdES4jException
    {
        SigningCertificateProperty scp = new SigningCertificateProperty(signingCertificateChain);
        formatSpecificSignedSigProps.add(scp);
    }
}
