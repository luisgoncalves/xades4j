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
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Document;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.properties.DataObjectDesc;
import xades4j.utils.ResolverAnonymous;
import xades4j.utils.TransformUtils;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static xades4j.production.SignerBES.idFor;

/**
 * Helper class that processes a set of data object descriptions.
 *
 * @author Luís
 */
final class SignedDataObjectsProcessor
{
    static final class Result
    {
        final Map<DataObjectDesc, Reference> referenceMappings;
        final Set<Manifest> manifests;

        public Result(Map<DataObjectDesc, Reference> referenceMappings, Set<Manifest> manifests)
        {
            this.referenceMappings = Collections.unmodifiableMap(referenceMappings);
            this.manifests = Collections.unmodifiableSet(manifests);
        }
    }

    private final SignatureAlgorithms signatureAlgorithms;
    private final AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller;

    @Inject
    SignedDataObjectsProcessor(SignatureAlgorithms signatureAlgorithms, AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller)
    {
        this.signatureAlgorithms = signatureAlgorithms;
        this.algorithmsParametersMarshaller = algorithmsParametersMarshaller;
    }

    /**
     * Processes the signed data objects and adds the corresponding {@code Reference}s
     * and {@code Object}s to the signature. This method must be invoked before
     * adding any other {@code Reference}s to the signature.
     *
     * @return result with reference mappings resulting from the data object descriptions and manifests to be digested
     * @throws UnsupportedAlgorithmException if the reference digest algorithm is not supported
     * @throws IllegalStateException         if the signature already contains {@code Reference}s
     */
    SignedDataObjectsProcessor.Result process(
            SignedDataObjects signedDataObjects,
            XMLSignature xmlSignature,
            ElementIdGenerator idGenerator) throws UnsupportedAlgorithmException {
        if (xmlSignature.getSignedInfo().getLength() != 0)
        {
            throw new IllegalStateException("XMLSignature already contains references");
        }

        return process(
                signedDataObjects.getDataObjectsDescs(),
                xmlSignature.getSignedInfo(),
                signedDataObjects.getResourceResolvers(),
                xmlSignature,
                false,
                idGenerator);
    }

    private SignedDataObjectsProcessor.Result process(
            Collection<? extends DataObjectDesc> dataObjects,
            Manifest container,
            List<ResourceResolverSpi> resourceResolvers,
            XMLSignature xmlSignature,
            boolean hasNullURIReference,
            ElementIdGenerator idGenerator) throws UnsupportedAlgorithmException {
        Map<DataObjectDesc, Reference> referenceMappings = new IdentityHashMap<>(dataObjects.size());
        Set<Manifest> manifests = new HashSet<>();

        for (ResourceResolverSpi resolver : resourceResolvers)
        {
            container.addResourceResolver(resolver);
        }

        String digestMethodUri = this.signatureAlgorithms.getDigestAlgorithmForDataObjectReferences();
        /**/
        try
        {
            for (DataObjectDesc dataObjDesc : dataObjects)
            {
                String refUri;
                String refType;
                int index = container.getLength();

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
                    // If the data object info is a EnvelopedXmlObject we need to create a ds:Object to embed it.
                    // The Reference uri will refer the new ds:Object's id.
                    EnvelopedXmlObject envXmlObj = (EnvelopedXmlObject) dataObjDesc;

                    ObjectContainer xmlObj = new ObjectContainer(container.getDocument());
                    String xmlObjId = idFor(xmlObj, idGenerator);
                    xmlObj.setId(xmlObjId);
                    xmlObj.appendChild(envXmlObj.getContent());
                    xmlObj.setMimeType(envXmlObj.getMimeType());
                    xmlObj.setEncoding(envXmlObj.getEncoding());
                    xmlSignature.appendObject(xmlObj);

                    refUri = '#' + xmlObjId;
                    refType = Reference.OBJECT_URI;
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
                    container.addResourceResolver(new ResolverAnonymous(anonymousRef.getDataStream()));
                }
                else if (dataObjDesc instanceof EnvelopedManifest)
                {
                    // If the data object info is a EnvelopedManifest we need to create a ds:Manifest and a ds:Object
                    // to embed it. The Reference uri will refer the manifest's id.
                    EnvelopedManifest envManifest = (EnvelopedManifest) dataObjDesc;

                    Manifest xmlManifest = new Manifest(container.getDocument());
                    String xmlManifestId = idFor(xmlManifest, idGenerator);
                    xmlManifest.setId(xmlManifestId);

                    SignedDataObjectsProcessor.Result manifestResult = process(
                            envManifest.getDataObjects(),
                            xmlManifest,
                            resourceResolvers,
                            xmlSignature,
                            hasNullURIReference,
                            idGenerator);

                    ObjectContainer xmlObj = new ObjectContainer(container.getDocument());
                    xmlObj.appendChild(xmlManifest.getElement());
                    xmlSignature.appendObject(xmlObj);

                    manifests.add(xmlManifest);
                    manifests.addAll(manifestResult.manifests);

                    refUri = '#' + xmlManifestId;
                    refType = Reference.MANIFEST_URI;
                }
                else
                {
                    throw new ClassCastException("Unsupported SignedDataObjectDesc. Must be one of DataObjectReference, EnvelopedXmlObject, EnvelopedManifest and AnonymousDataObjectReference");
                }

                Transforms transforms = processTransforms(dataObjDesc, container.getDocument());

                // Add the Reference. References need an ID because data object properties may refer them.
                container.addDocument(
                        xmlSignature.getBaseURI(),
                        refUri,
                        transforms,
                        digestMethodUri,
                        null,
                        refType);

                // SignedDataObjects and EnvelopedManifest don't allow repeated instances, so there's no
                // need to check for duplicate entries on the map.
                Reference ref = container.item(index);
                ref.setId(idFor(ref, idGenerator));
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

        return new Result(referenceMappings, manifests);
    }

    private Transforms processTransforms(
            DataObjectDesc dataObjDesc,
            Document document) throws UnsupportedAlgorithmException
    {
        Collection<Algorithm> transforms = dataObjDesc.getTransforms();
        if (transforms.isEmpty())
        {
            return null;
        }

        return TransformUtils.createTransforms(document, this.algorithmsParametersMarshaller, transforms);
    }
}
