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
package xades4j.properties;

/**
 * Base class for the {@code SignaturePolicyIdentifier} property. The signature
 * policy identifier is a signed property qualifying the signature. At most one
 * {@code SignaturePolicyIdentifier} element may be present in the signature.
 * <p>
 * Although there is only one XML element indicating if the signature policiy is
 * explicit or implied, two different classes exist to represent those situations.
 * <p>
 * This property cannot be supplied directly. It is enforced by the {@link xades4j.production.XadesSigner}
 * producing a XAdES-EPES.
 * @see SignaturePolicyImpliedProperty
 * @see SignaturePolicyIdentifierProperty
 * @author Luís
 */
public abstract class SignaturePolicyBase extends SignedSignatureProperty
{
    public static final String PROP_NAME = "SignaturePolicyIdentifier";

    @Override
    public final String getName()
    {
        return PROP_NAME;
    }
}
