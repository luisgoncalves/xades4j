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
package xades4j.properties;

import java.util.Collection;
import java.util.List;
import org.w3c.dom.Element;
import xades4j.utils.CollectionUtils;

/**
 * Base class for the {@code CommitmentTypeIndication} property. This is a signed property
 * that qualifies signed data objects. In consequence, XAdES signatures may contain
 * more than one {@code CommitmentTypeIndication}.
 * <p>
 * Although the same XML element is used when the property applies to some or all
 * data objects there two different types in order to control the number of targets:
 * if the commitment applies to all the signed data objects {@link AllDataObjsCommitmentTypeProperty AllDataObjsCommitmentTypeProperty}
 * should be used; otherwise use {@link CommitmentTypeProperty CommitmentTypeProperty}.
 *
 * @author Luís
 */
public abstract class CommitmentTypePropertyBase extends SignedDataObjectProperty
{
    public static final String PROOF_OF_ORIGIN_URI = "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin",
            PROOF_OF_ORIGIN_DESC = "Indicates that the signer recognizes to have created, approved and sent the signed data object",
            PROOF_OF_RECEIPT_URI = "http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt",
            PROOF_OF_RECEIPT_DESC = "Indicates that signer recognizes to have received the content of the signed data object",
            PROOF_OF_DELIVERY_URI = "http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery",
            PROOF_OF_DELIVERY_DESC = "Indicates that the TSP providing that indication has delivered a signed data object in a local store accessible to the recipient of the signed data object",
            PROOF_OF_SENDER_URI = "http://uri.etsi.org/01903/v1.2.2#ProofOfSender",
            PROOF_OF_SENDER_DESC = "Indicates that the entity providing that indication has sent the signed data object (but not necessarily created it)",
            PROOF_OF_APPROVAL_URI = "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval",
            PROOF_OF_APPROVAL_DESC = "Indicates that the signer has approved the content of the signed data object",
            PROOF_OF_CREATION_URI = "http://uri.etsi.org/01903/v1.2.2#ProofOfCreation",
            PROOF_OF_CREATION_DESC = "Indicates that the signer has created the signed data object (but not necessarily approved, nor sent it)";
    public static final String PROP_NAME = "CommitmentTypeIndication";
    /**/
    private final String uri, description;
    private Collection qualifiers;

    protected CommitmentTypePropertyBase(String uri, String description,
            TargetMultiplicity targetMult)
    {
        super(targetMult);
        this.uri = uri;
        this.description = description;
    }

    /**
     * Gets the description of this commitment type.
     * @return the description
     */
    public String getDescription()
    {
        return this.description;
    }
    /**
     * Gets the URI of this commitment type.
     * @return the URI
     */
    public String getUri()
    {
        return this.uri;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
    
    public CommitmentTypePropertyBase withQualifier(String qualifier){
        return this.addQualifier(qualifier);
    }
    
    public CommitmentTypePropertyBase withQualifier(Element qualifier){
        return this.addQualifier(qualifier);
    }
    
    private CommitmentTypePropertyBase addQualifier(Object qualifier){
        this.qualifiers = CollectionUtils.newIfNull(this.qualifiers, 2);
        this.qualifiers.add(qualifier);
        return this;
    }
    
    public Collection getQualifiers(){
        return CollectionUtils.emptyIfNull(this.qualifiers);
    }
}
