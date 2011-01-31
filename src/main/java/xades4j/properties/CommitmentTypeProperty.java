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

/**
 * A commitment type that applies to some signed data objects. The class has
 * helper methods to get new instances representing a number of commitments that
 * have been already identified in TS 101 733.
 *
 * @see CommitmentTypePropertyBase
 * @author Luís
 */
public final class CommitmentTypeProperty extends CommitmentTypePropertyBase
{
    /**
     * Gets an {@code CommitmentTypeProperty} representing the <i>Proof of origin</i>
     * commitment. Indicates that the signer recognizes to have created, approved
     * and sent the signed data object.
     * @return a new instance with the commitment information
     */
    public static CommitmentTypeProperty proofOfOrigin()
    {
        return new CommitmentTypeProperty(PROOF_OF_ORIGIN_URI, PROOF_OF_ORIGIN_DESC);
    }

    /**
     * Gets an {@code CommitmentTypeProperty} representing the <i>Proof of receipt</i>
     * commitment. Indicates that signer recognizes to have received the content
     * of the signed data object.
     * @return a new instance with the commitment information
     */
    public static CommitmentTypeProperty proofOfReceipt()
    {
        return new CommitmentTypeProperty(PROOF_OF_RECEIPT_URI, PROOF_OF_RECEIPT_DESC);
    }

    /**
     * Gets an {@code CommitmentTypeProperty} representing the <i>Proof of delivery</i>
     * commitment. Indicates that the TSP providing that indication has delivered
     * a signed data object in a local store accessible to the recipient of the
     * signed data object.
     * @return a new instance with the commitment information
     */
    public static CommitmentTypeProperty proofOfDelivery()
    {
        return new CommitmentTypeProperty(PROOF_OF_DELIVERY_URI, PROOF_OF_DELIVERY_DESC);
    }

    /**
     * Gets an {@code CommitmentTypeProperty} representing the <i>Proof of sender</i>
     * commitment. Indicates that the entity providing the indication has sent
     * the signed data object (but not necessarily created it).
     * @return a new instance with the commitment information
     */
    public static CommitmentTypeProperty proofOfSender()
    {
        return new CommitmentTypeProperty(PROOF_OF_SENDER_URI, PROOF_OF_SENDER_DESC);
    }

    /**
     * Gets an {@code CommitmentTypeProperty} representing the <i>Proof of approval</i>
     * commitment. Indicates that the signer has approved the content of the signed
     * data object.
     * @return a new instance with the commitment information
     */
    public static CommitmentTypeProperty proofOfApproval()
    {
        return new CommitmentTypeProperty(PROOF_OF_APPROVAL_URI, PROOF_OF_APPROVAL_DESC);
    }

    /**
     * Gets an {@code CommitmentTypeProperty} representing the <i>Proof of origin</i>
     * commitment. Indicates that the signer has created the signed data object
     * (but not necessarily approved, nor sent it).
     * @return a new instance with the commitment information
     */
    public static CommitmentTypeProperty proofOfCreation()
    {
        return new CommitmentTypeProperty(PROOF_OF_CREATION_URI, PROOF_OF_CREATION_DESC);
    }
    /**/

    /**
     * @param uri the commitment type URI
     * @param description teh commitment type description
     */
    public CommitmentTypeProperty(String uri, String description)
    {
        super(uri, description, SignedDataObjectProperty.TargetMultiplicity.N);
    }
}
