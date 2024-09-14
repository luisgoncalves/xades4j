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

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.XAdES4jXMLSigException;
import xades4j.properties.DataObjectDesc;
import xades4j.utils.DOMHelper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static xades4j.production.SignerBES.idFor;
import static xades4j.utils.StringUtils.isNullOrEmptyString;

/**
 * Context used during the generation of the properties low-level data (property
 * data objects). Contains informations about the algorithms in use and the resources
 * being signed.
 *
 * @author Luís
 * @see PropertiesDataObjectsGenerator
 */
public final class PropertiesDataGenerationContext
{
    private final List<Reference> references;
    private final Map<DataObjectDesc, Reference> referencesMappings;
    private final Document sigDocument;
    private final ElementIdGenerator idGenerator;
    private XMLSignature targetXmlSignature;

    /**
     * A simple constructor to be used when only unsigned signature properties
     * will be processed.
     *
     * @param targetXmlSignature the target signature
     * @param idGenerator        ID generator
     */
    PropertiesDataGenerationContext(XMLSignature targetXmlSignature, ElementIdGenerator idGenerator) throws XAdES4jXMLSigException
    {
        this.targetXmlSignature = targetXmlSignature;
        this.sigDocument = targetXmlSignature.getDocument();
        this.referencesMappings = null;
        this.idGenerator = idGenerator;

        SignedInfo signedInfo = targetXmlSignature.getSignedInfo();
        List<Reference> refs = new ArrayList<>(signedInfo.getLength());
        for (int i = 0; i < signedInfo.getLength(); i++)
        {
            try
            {
                refs.add(signedInfo.item(i));
            }
            catch (XMLSecurityException ex)
            {
                throw new XAdES4jXMLSigException(String.format("Cannot process the %dth reference", i), ex);
            }
        }
        this.references = Collections.unmodifiableList(refs);
    }

    /**
     * @param orderedDataObjs
     * @param referencesMappings should be unmodifiable
     * @param sigDocument
     */
    PropertiesDataGenerationContext(
            Collection<DataObjectDesc> orderedDataObjs,
            Map<DataObjectDesc, Reference> referencesMappings,
            Document sigDocument,
            ElementIdGenerator idGenerator)
    {
        this.referencesMappings = referencesMappings;
        this.sigDocument = sigDocument;
        this.idGenerator = idGenerator;

        List<Reference> orderedRefs = new ArrayList<>(orderedDataObjs.size());
        for (DataObjectDesc dataObjDesc : orderedDataObjs)
        {
            orderedRefs.add(referencesMappings.get(dataObjDesc));
        }

        this.references = Collections.unmodifiableList(orderedRefs);
    }

    /**
     * Gets all the {@code Reference}s present in the signature that is being
     * created, except the signed properties reference, in order of appearence
     * within {@code SignedInfo}.
     *
     * @return the unmodifiable list of {@code Reference}s
     */
    public List<Reference> getReferences()
    {
        return references;
    }

    /**
     * Gets the {@code Reference} that corresponds to a given high-level {@code DataObjectDesc}.
     *
     * @param dataObject the signed data object
     * @return the reference
     */
    public Reference getReference(DataObjectDesc dataObject)
    {
        return referencesMappings.get(dataObject);
    }

    public String ensureElementId(Reference element)
    {
        String id = element.getId();
        if (isNullOrEmptyString(id))
        {
            id = idFor(element, idGenerator);
            element.setId(id);
        }

        return id;
    }

    public String ensureElementId(Element element)
    {
        String id = element.getAttribute(Constants._ATT_ID);
        if (isNullOrEmptyString(id))
        {
            id = idFor(element, idGenerator);
            DOMHelper.setIdAsXmlId(element, id);
        }
        return id;
    }

    XMLSignature getTargetXmlSignature()
    {
        if (this.targetXmlSignature == null)
        {
            throw new IllegalStateException("Target XMLSignature not set");
        }
        return targetXmlSignature;
    }

    void setTargetXmlSignature(XMLSignature targetXmlSignature)
    {
        if (this.targetXmlSignature != null)
        {
            throw new IllegalStateException("Target XMLSignature already set");
        }
        this.targetXmlSignature = targetXmlSignature;
    }

    /**
     * Creates a DOM {@code Element} in the signature's document. This can be useful
     * when generating {@link xades4j.properties.data.GenericDOMData} data objects.
     *
     * @param name      the local name of the element
     * @param namespace the namespace where the element will be created
     * @return the created element
     */
    public Element createElementInSignatureDoc(String name, String prefix, String namespace)
    {
        return DOMHelper.createElement(this.sigDocument, name, prefix, namespace);
    }
}
