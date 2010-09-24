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
package xades4j.production;

import org.w3c.dom.Node;
import xades4j.XAdES4jException;

/**
 * Interface for a producer of signatures. The features of the produced signatures
 * depend on the profile configuration.
 * <p>
 * All the exceptions defined in the current package may be thrown during production.
 * They are organized as a tree which means that one can go from rough to fine-grained
 * handling by catching exceptions in the different branches/depths of the tree.
 * 
 * @see XadesSigningProfile
 * @author Luís
 */
public interface XadesSigner
{
    /**
     * Applies a signature over a set of data objects and appends it to the given
     * node.
     * @param signedDataObjects the data objects to be signed
     * @param parent the node to which the signature element will be appended
     * @return the signature result
     * @see SignedDataObjects
     * @throws XAdES4jException if an error occurs
     */
    public XadesSignatureResult sign(
            SignedDataObjects signedDataObjects,
            Node parent) throws XAdES4jException;
}
