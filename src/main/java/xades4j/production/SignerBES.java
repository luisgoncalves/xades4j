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
package xades4j.production;

import jakarta.inject.Inject;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.UnsupportedAlgorithmException;
import xades4j.XAdES4jException;
import xades4j.XAdES4jXMLSigException;
import xades4j.algorithms.Algorithm;
import xades4j.properties.QualifyingProperties;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.SigningCertificateProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.properties.data.SigAndDataObjsPropertiesData;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.ValidationDataException;
import xades4j.providers.X500NameStyleProvider;
import xades4j.utils.DOMHelper;
import xades4j.utils.ObjectUtils;
import xades4j.utils.StringUtils;
import xades4j.utils.TransformUtils;
import xades4j.xml.marshalling.SignedPropertiesMarshaller;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static xades4j.utils.CanonicalizerUtils.checkC14NAlgorithm;

/**
 * Base logic for producing XAdES signatures (XAdES-BES).
 *
 * @author Luís
 */
class SignerBES implements XadesSigner
{

    static
    {
        Init.initXMLSec();
    }

    /**/
    private final KeyingDataProvider keyingProvider;
    private final SignatureAlgorithms signatureAlgorithms;
    private final BasicSignatureOptions basicSignatureOptions;
    private final SignedDataObjectsProcessor dataObjectDescsProcessor;
    private final PropertiesDataObjectsGenerator propsDataObjectsGenerator;
    private final SignedPropertiesMarshaller signedPropsMarshaller;
    private final UnsignedPropertiesMarshaller unsignedPropsMarshaller;
    private final AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller;
    private final ElementIdGeneratorFactory idGeneratorFactory;
    /**/
    private final KeyInfoBuilder keyInfoBuilder;
    private final QualifyingPropertiesProcessor qualifPropsProcessor;

    @Inject
    protected SignerBES(
            KeyingDataProvider keyingProvider,
            SignatureAlgorithms signatureAlgorithms,
            BasicSignatureOptions basicSignatureOptions,
            SignedDataObjectsProcessor dataObjectDescsProcessor,
            SignaturePropertiesProvider signaturePropsProvider,
            DataObjectPropertiesProvider dataObjPropsProvider,
            PropertiesDataObjectsGenerator propsDataObjectsGenerator,
            SignedPropertiesMarshaller signedPropsMarshaller,
            UnsignedPropertiesMarshaller unsignedPropsMarshaller,
            AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller,
            X500NameStyleProvider x500NameStyleProvider,
            ElementIdGeneratorFactory idGeneratorFactory)
    {
        if (ObjectUtils.anyNull(
                keyingProvider, signatureAlgorithms, basicSignatureOptions,
                signaturePropsProvider, dataObjPropsProvider, propsDataObjectsGenerator,
                signedPropsMarshaller, unsignedPropsMarshaller, algorithmsParametersMarshaller,
                x500NameStyleProvider, idGeneratorFactory))
        {
            throw new NullPointerException("One or more arguments are null");
        }

        this.keyingProvider = keyingProvider;
        this.signatureAlgorithms = signatureAlgorithms;
        this.basicSignatureOptions = basicSignatureOptions;
        this.propsDataObjectsGenerator = propsDataObjectsGenerator;
        this.signedPropsMarshaller = signedPropsMarshaller;
        this.unsignedPropsMarshaller = unsignedPropsMarshaller;
        this.algorithmsParametersMarshaller = algorithmsParametersMarshaller;
        this.dataObjectDescsProcessor = dataObjectDescsProcessor;
        this.idGeneratorFactory = idGeneratorFactory;
        this.keyInfoBuilder = new KeyInfoBuilder(basicSignatureOptions, signatureAlgorithms, algorithmsParametersMarshaller, x500NameStyleProvider);
        this.qualifPropsProcessor = new QualifyingPropertiesProcessor(signaturePropsProvider, dataObjPropsProvider);
    }

    @Override
    public final XadesSignatureResult sign(
            SignedDataObjects signedDataObjects,
            Node parent) throws XAdES4jException
    {
        return sign(signedDataObjects, parent, SignatureAppendingStrategies.AsLastChild);
    }

    @Override
    public final XadesSignatureResult sign(
            SignedDataObjects signedDataObjects,
            Node referenceNode,
            SignatureAppendingStrategy appendingStrategy) throws XAdES4jException
    {
        if (null == referenceNode)
        {
            throw new NullPointerException("Reference node node cannot be null");
        }
        if (null == signedDataObjects)
        {
            throw new NullPointerException("References cannot be null");
        }
        if (signedDataObjects.isEmpty())
        {
            throw new IllegalArgumentException("Data objects list is empty");
        }

        this.basicSignatureOptions.ensureValid();

        Document signatureDocument = DOMHelper.getOwnerDocument(referenceNode);
        ElementIdGenerator idGenerator = this.idGeneratorFactory.create();


        // Signing certificate chain (may contain only the signing certificate).
        List<X509Certificate> signingCertificateChain = this.keyingProvider.getSigningCertificateChain();
        if (null == signingCertificateChain || signingCertificateChain.isEmpty())
        {
            throw new SigningCertChainException("Signing certificate not provided");
        }
        X509Certificate signingCertificate = signingCertificateChain.get(0);

        // The XMLSignature (ds:Signature).
        XMLSignature signature = createSignature(
                signatureDocument,
                signedDataObjects.getBaseUri(),
                signingCertificate.getPublicKey().getAlgorithm());

        String signatureId = idFor(signature, idGenerator);
        signature.setId(signatureId);

        /* References */
        // Process the data object descriptions to get the References and mappings.
        // After this call all the signed data objects References and XMLObjects
        // are added to the signature.
        SignedDataObjectsProcessor.Result signedDataObjectsResult = this.dataObjectDescsProcessor.process(
                signedDataObjects,
                signature,
                idGenerator);

        /* ds:KeyInfo */
        this.keyInfoBuilder.buildKeyInfo(signingCertificateChain, signature, idGenerator);

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
        }
        catch (XMLSignatureException ex)
        {
            // -> xmlSignature.appendObject(xmlObj): not thrown when signing.
            throw new IllegalStateException(ex);
        }

        /* Collect the properties */
        // Get the format specific signature properties.
        Collection<SignedSignatureProperty> fsssp = new ArrayList<>(2);
        Collection<UnsignedSignatureProperty> fsusp = new ArrayList<>(2);
        getFormatSpecificSignatureProperties(fsssp, fsusp, signingCertificateChain);
        // Gather all the signature and data objects properties.
        QualifyingProperties qualifProps = qualifPropsProcessor.getQualifyingProperties(
                signedDataObjects, fsssp, fsusp);

        try
        {
            // The signature needs to be appended to the document from now on because
            // property data generation may need to dereference same-document data
            // object references.
            appendingStrategy.append(signature.getElement(), referenceNode);

            // Digest manifests because property data generation may need to get Reference digest values
            digestManifests(signedDataObjectsResult.manifests);

            /* Signed properties */
            // Create the context for signed properties data objects generation.
            PropertiesDataGenerationContext propsDataGenCtx = new PropertiesDataGenerationContext(
                    signedDataObjects.getDataObjectsDescs(),
                    signedDataObjectsResult.referenceMappings,
                    signatureDocument,
                    idGenerator);
            // Generate the signed properties data objects. The data objects structure
            // is verifier in the process.
            SigAndDataObjsPropertiesData signedPropsData = this.propsDataObjectsGenerator.generateSignedPropertiesData(
                    qualifProps.getSignedProperties(),
                    propsDataGenCtx);
            // Marshal the signed properties data to the QualifyingProperties node.
            this.signedPropsMarshaller.marshal(signedPropsData, qualifyingPropsElem);
            Element signedPropsElem = DOMHelper.getFirstChildElement(qualifyingPropsElem);
            String signedPropsId = idFor(signedPropsElem, idGenerator);
            DOMHelper.setIdAsXmlId(signedPropsElem, signedPropsId);

            // SignedProperties reference
            // XAdES 6.3.1: "In order to protect the properties with the signature,
            // a ds:Reference element MUST be added to the XMLDSIG signature (...)
            // composed in such a way that it uses the SignedProperties element (...)
            // as the input for computing its corresponding digest. Additionally,
            // (...) use the Type attribute of this particular ds:Reference element,
            // with its value set to: http://uri.etsi.org/01903#SignedProperties."

            String digestAlgUri = getDigestAlgUri();

            // Use same canonicalization URI as specified in the ds:CanonicalizationMethod for Signature.
            Algorithm canonAlg = this.signatureAlgorithms.getCanonicalizationAlgorithmForSignature();

            try
            {
                checkC14NAlgorithm(canonAlg);
                Transforms transforms = TransformUtils.createTransforms(canonAlg, this.algorithmsParametersMarshaller, signatureDocument);

                signature.addDocument('#' + signedPropsId, transforms, digestAlgUri, null, QualifyingProperty.SIGNED_PROPS_TYPE_URI);
            }
            catch (XMLSignatureException ex)
            {
                // Seems to be thrown when the digest algorithm is not supported. In
                // this case, if it wasn't thrown when processing the data objects it
                // shouldn't be thrown now!
                throw new UnsupportedAlgorithmException(
                        "Digest algorithm not supported in the XML Signature provider",
                        digestAlgUri, ex);
            }

            // Apply the signature
            try
            {
                PrivateKey signingKey = keyingProvider.getSigningKey(signingCertificate);
                signature.sign(signingKey);
            }
            catch (XMLSignatureException ex)
            {
                throw new XAdES4jXMLSigException(ex.getMessage(), ex);
            }

            /* Marshal unsigned properties */
            // Generate the unsigned properties data objects. The data objects structure
            // is verifier in the process.
            propsDataGenCtx.setTargetXmlSignature(signature);
            SigAndDataObjsPropertiesData unsignedPropsData = this.propsDataObjectsGenerator.generateUnsignedPropertiesData(
                    qualifProps.getUnsignedProperties(),
                    propsDataGenCtx);
            // Marshal the unsigned properties to the final QualifyingProperties node.
            this.unsignedPropsMarshaller.marshal(unsignedPropsData, qualifyingPropsElem);
        }
        catch (XAdES4jException ex)
        {
            appendingStrategy.revert(signature.getElement(), referenceNode);
            throw ex;
        }

        return new XadesSignatureResult(signature, qualifProps);
    }

    private String getDigestAlgUri()
    {
        String digestAlgUri = this.signatureAlgorithms.getDigestAlgorithmForDataObjectReferences();
        if (StringUtils.isNullOrEmptyString(digestAlgUri))
        {
            throw new NullPointerException("Digest algorithm URI not provided");
        }
        return digestAlgUri;
    }

    private XMLSignature createSignature(Document signatureDocument, String baseUri, String signingKeyAlgorithm) throws XAdES4jXMLSigException, UnsupportedAlgorithmException
    {
        Algorithm signatureAlg = this.signatureAlgorithms.getSignatureAlgorithm(signingKeyAlgorithm);
        Element signatureAlgElem = createElementForAlgorithm(signatureAlg, Constants._TAG_SIGNATUREMETHOD, signatureDocument);

        Algorithm canonAlg = this.signatureAlgorithms.getCanonicalizationAlgorithmForSignature();
        if (null == canonAlg)
        {
            throw new NullPointerException("Canonicalization algorithm not provided");
        }
        Element canonAlgElem = createElementForAlgorithm(canonAlg, Constants._TAG_CANONICALIZATIONMETHOD, signatureDocument);

        try
        {
            return new XMLSignature(signatureDocument, baseUri, signatureAlgElem, canonAlgElem);
        }
        catch (XMLSecurityException ex)
        {
            // Following the code, doesn't seem to be thrown at all.
            throw new XAdES4jXMLSigException(ex.getMessage(), ex);
        }
    }

    private Element createElementForAlgorithm(Algorithm algorithm, String elementName, Document signatureDocument) throws UnsupportedAlgorithmException
    {
        Element algorithmElem = XMLUtils.createElementInSignatureSpace(signatureDocument, elementName);
        algorithmElem.setAttributeNS(null, Constants._ATT_ALGORITHM, algorithm.getUri());

        List<Node> algorithmParams = this.algorithmsParametersMarshaller.marshalParameters(algorithm, signatureDocument);
        if (algorithmParams != null)
        {
            for (Node p : algorithmParams)
            {
                algorithmElem.appendChild(p);
            }
        }
        return algorithmElem;
    }

    private static void digestManifests(Iterable<Manifest> manifests) throws XAdES4jXMLSigException
    {
        try
        {
            for (Manifest m : manifests)
            {
                m.generateDigestValues();
            }
        }
        catch (XMLSignatureException ex)
        {
            throw new XAdES4jXMLSigException("Error digesting manifest", ex);
        }
    }

    /**
     * Override in subclasses to collect the signature properties that are mandatory
     * in the corresponding format.
     */
    protected void getFormatSpecificSignatureProperties(
            Collection<SignedSignatureProperty> formatSpecificSignedSigProps,
            Collection<UnsignedSignatureProperty> formatSpecificUnsignedSigProps,
            List<X509Certificate> signingCertificateChain) throws ValidationDataException
    {
        if (!this.basicSignatureOptions.omitSigningCertificateProperty())
        {
            SigningCertificateProperty scp = new SigningCertificateProperty(signingCertificateChain);
            formatSpecificSignedSigProps.add(scp);
        }
    }

    public static String idFor(ElementProxy elementProxy, ElementIdGenerator idGenerator)
    {
        return idGenerator.generateId(elementProxy.getBaseNamespace(), elementProxy.getBaseLocalName());
    }

    public static String idFor(Element element, ElementIdGenerator idGenerator)
    {
        return idGenerator.generateId(element.getNamespaceURI(), element.getLocalName());
    }
}
