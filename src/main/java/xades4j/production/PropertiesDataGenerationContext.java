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

import xades4j.properties.DataObjectDesc;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.XAdES4jXMLSigException;
import xades4j.utils.DOMHelper;

/**
 * Context used during the generation of the properties low-level data (property
 * data objects). Contains informations about the algorithms in use and the resources
 * being signed.
 * 
 * @see PropertiesDataObjectsGenerator
 * @author Luís
 */
public class PropertiesDataGenerationContext
{

    private final List<Reference> references;
    private final Map<DataObjectDesc, Reference> referencesMappings;
    private final Document sigDocument;
    private XMLSignature targetXmlSignature;

    /**
     * A simple constructor to be used when only unsigned signature properties
     * will be processed.
     * @param targetXmlSignature the target signature
     * @param algorithmsProvider algorithms in use
     */
    PropertiesDataGenerationContext(XMLSignature targetXmlSignature) throws XAdES4jXMLSigException
    {
        this.targetXmlSignature = targetXmlSignature;
        this.sigDocument = targetXmlSignature.getDocument();
        this.referencesMappings = null;

        SignedInfo signedInfo = targetXmlSignature.getSignedInfo();
        List<Reference> refs = new ArrayList<Reference>(signedInfo.getLength());
        for (int i = 0; i < signedInfo.getLength(); i++)
        {
            try
            {
                refs.add(signedInfo.item(i));
            } catch (XMLSecurityException ex)
            {
                throw new XAdES4jXMLSigException(String.format("Cannot process the %dth reference", i), ex);
            }
        }
        this.references = Collections.unmodifiableList(refs);
    }

    /**
     * @param orderedDataObjs
     * @param referencesMappings should be unmodifiable
     * @param elemInSigDoc
     * @param algorithmsProvider
     */
    PropertiesDataGenerationContext(
            Collection<DataObjectDesc> orderedDataObjs,
            Map<DataObjectDesc, Reference> referencesMappings,
            Document sigDocument)
    {
        this.referencesMappings = referencesMappings;
        this.sigDocument = sigDocument;

        List<Reference> orderedRefs = new ArrayList<Reference>(orderedDataObjs.size());
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
     * @return the unmodifiable list of {@code Reference}s
     */
    public List<Reference> getReferences()
    {
        return references;
    }

    /**
     * Gets the mappings from high-level {@code DataObjectDesc}s to {@code Reference}s.
     * This should be used when a data object property needs any information from
     * the {@code Reference} that corresponds to the data object.
     * @return the unmodifiable mapping
     */
    public Map<DataObjectDesc, Reference> getReferencesMappings()
    {
        return referencesMappings;
    }

    /**
     * Gets the XML Signature that is being created. This is only available when
     * generating unisgned properties data objects.
     * @return the target signature or {@code null} if not yet available
     */
    public XMLSignature getTargetXmlSignature()
    {
        return targetXmlSignature;
    }

    void setTargetXmlSignature(XMLSignature targetXmlSignature)
    {
        if (this.targetXmlSignature != null)
        {
            throw new IllegalStateException("TargetXMLSignature already set");
        }
        this.targetXmlSignature = targetXmlSignature;
    }

    Document getSignatureDocument()
    {
        return this.sigDocument;
    }

    /**
     * Creates a DOM {@code Element} in the signature's document. This can be useful
     * when generating {@link xades4j.properties.data.GenericDOMData} data objects.
     * @param name the local name of the element
     * @param namespace the namespace where the element will be created
     * @return the created element
     */
    public Element createElementInSignatureDoc(String name, String prefix, String namespace)
    {
        return DOMHelper.createElement(this.sigDocument, name, prefix, namespace);
    }
}
