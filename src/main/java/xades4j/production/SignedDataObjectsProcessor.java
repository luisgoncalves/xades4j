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

import xades4j.algorithms.Algorithm;
import com.google.inject.Inject;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverAnonymous;
import org.w3c.dom.Document;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.utils.TransformUtils;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 * Helper class that processes a set of data object descriptions.
 * 
 * @author Luís
 */
class SignedDataObjectsProcessor
{
    private final AlgorithmsProviderEx algorithmsProvider;
    private final AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller;

    @Inject
    SignedDataObjectsProcessor(AlgorithmsProviderEx algorithmsProvider, AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller)
    {
        this.algorithmsProvider = algorithmsProvider;
        this.algorithmsParametersMarshaller = algorithmsParametersMarshaller;
    }

    /**
     * Processes the signed data objects and adds the corresponding {@code Reference}s
     * and {@code Object}s to the signature. This method must be invoked before
     * adding any other {@code Reference}s to the signature.
     * 
     * @return the reference mappings resulting from the data object descriptions.
     * 
     * @throws UnsupportedAlgorithmException
     * @throws IllegalStateException if the signature already contains {@code Reference}s
     */
    Map<DataObjectDesc, Reference> process(
            SignedDataObjects signedDataObjects,
            XMLSignature xmlSignature) throws UnsupportedAlgorithmException
    {
        if(xmlSignature.getSignedInfo().getLength() != 0)
        {
            throw new IllegalStateException("XMLSignature already contais references");
        }
        
        for (ResourceResolver resolver : signedDataObjects.getResourceResolvers())
        {
            xmlSignature.addResourceResolver(resolver);
        }

        Collection<DataObjectDesc> dataObjsDescs = signedDataObjects.getDataObjectsDescs();
        Map<DataObjectDesc, Reference> referenceMappings = new IdentityHashMap<DataObjectDesc, Reference>(dataObjsDescs.size());

        String refUri, refType;
        Transforms transforms;
        String digestMethodUri = this.algorithmsProvider.getDigestAlgorithmForDataObjsReferences();
        boolean hasNullURIReference = false;
        /**/
        try
        {
            for (DataObjectDesc dataObjDesc : dataObjsDescs)
            {
                transforms = processTransforms(dataObjDesc, xmlSignature.getDocument());

                if (dataObjDesc instanceof DataObjectReference)
                {
                    // If the data object info is a DataObjectReference, the Reference uri
                    // and type are the ones specified on the object.
                    DataObjectReference dataObjRef = (DataObjectReference) dataObjDesc;
                    refUri = dataObjRef.getUri();
                    refType = dataObjRef.getType();
                }
                else if (dataObjDesc instanceof EnvelopedXmlObject)
                {
                    // If the data object info is a EnvelopedXmlObject we need to create a
                    // XMLObject to embed it. The Reference uri will refer the new
                    // XMLObject's id.
                    EnvelopedXmlObject envXmlObj = (EnvelopedXmlObject) dataObjDesc;
                    refUri = String.format("%s-object%d", xmlSignature.getId(), xmlSignature.getObjectLength());
                    refType = Reference.OBJECT_URI;

                    ObjectContainer xmlObj = new ObjectContainer(xmlSignature.getDocument());
                    xmlObj.setId(refUri);
                    xmlObj.appendChild(envXmlObj.getContent());
                    xmlObj.setMimeType(envXmlObj.getMimeType());
                    xmlObj.setEncoding(envXmlObj.getEncoding());
                    xmlSignature.appendObject(xmlObj);

                    refUri = '#' + refUri;
                }
                else if (dataObjDesc instanceof AnonymousDataObjectReference)
                {
                    if (hasNullURIReference)
                    {
                        // This shouldn't happen because SignedDataObjects does the validation.
                        throw new IllegalStateException("Multiple AnonymousDataObjectReference detected");
                    }
                    hasNullURIReference = true;

                    refUri = refType = null;
                    AnonymousDataObjectReference anonymousRef = (AnonymousDataObjectReference) dataObjDesc;
                    xmlSignature.addResourceResolver(new ResolverAnonymous(anonymousRef.getDataStream()));
                }
                else
                {
                    throw new ClassCastException("Unsupported SignedDataObjectDesc. Must be one of DataObjectReference, EnvelopedXmlObject and AnonymousDataObjectReference");
                }

                // Add the Reference. References need an ID because data object
                // properties may refer them.
                xmlSignature.addDocument(
                        refUri,
                        transforms,
                        digestMethodUri,
                        String.format("%s-ref%d", xmlSignature.getId(), referenceMappings.size()), // id
                        refType);

                // SignedDataObjects doesn't allow repeated instances, so there's no
                // need to check for duplicate entries on the map.
                Reference ref = xmlSignature.getSignedInfo().item(referenceMappings.size());
                referenceMappings.put(dataObjDesc, ref);
            }

        } catch (XMLSignatureException ex)
        {
            // -> xmlSignature.appendObject(xmlObj): not thrown when signing.
            // -> xmlSignature.addDocument(...): appears to be thrown when the digest
            //      algorithm is not supported.
            throw new UnsupportedAlgorithmException(
                    "Digest algorithm not supported in the XML Signature provider",
                    digestMethodUri, ex);
        } catch (org.apache.xml.security.exceptions.XMLSecurityException ex)
        {
            // -> xmlSignature.getSignedInfo().item(...): shouldn't be thrown
            //      when signing.
            throw new IllegalStateException(ex);
        }

        return Collections.unmodifiableMap(referenceMappings);
    }

    private Transforms processTransforms(
            DataObjectDesc dataObjDesc,
            Document document) throws UnsupportedAlgorithmException
    {
        Collection<Algorithm> dObjTransfs = dataObjDesc.getTransforms();
        if (dObjTransfs.isEmpty())
        {
            return null;
        }

        return TransformUtils.createTransforms(document, this.algorithmsParametersMarshaller, dObjTransfs);
    }
}
