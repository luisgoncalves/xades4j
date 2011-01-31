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
package xades4j.providers;

import xades4j.properties.SigningTimeProperty;
import xades4j.properties.SignatureProductionPlaceProperty;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.OtherUnsignedSignatureProperty;
import xades4j.properties.OtherSignedSignatureProperty;
import xades4j.properties.SignerRoleProperty;

/**
 * Interface for the collector of signature properties.
 *
 * @see SignaturePropertiesProvider#provideProperties(xades4j.providers.SignaturePropertiesCollector)
 * @author Luís
 */
public interface SignaturePropertiesCollector
{
    /**
     * Sets the {@code SigningTime} signed property. This can be set only once.
     * @param sigTime the {@code SigningTime} property
     * @throws NullPointerException if {@code sigTime} is {@code null}
     * @throws PropertyTargetException if {@code SigningTime} is set more than once
     */
    public void setSigningTime(SigningTimeProperty sigTime);

    /**
     * Sets the {@code SignatureProductionPlace} signed property. This can be set
     * only once.
     * @param sigProdPlace the {@code SignatureProductionPlace} property
     * @throws NullPointerException if {@code sigProdPlace} is {@code null}
     * @throws PropertyTargetException if {@code SignatureProductionPlace} is set more than once
     */
    public void setSignatureProductionPlace(
            SignatureProductionPlaceProperty sigProdPlace);

    /**
     * Sets the {@code SignerRole} signed property. This can be set only once.
     * @param signerRole the {@code SignerRole} property.
     * @throws NullPointerException if {@code signerRole} is {@code null}
     * @throws PropertyTargetException if {@code SignerRole} is set more than once
     */
    public void setSignerRole(SignerRoleProperty signerRole);

    /**
     * Adds a {@code CounterSignature} unsigned property. Multiple counter signatures
     * can be added.
     * @param counterSig the {@code CounterSignature} property
     * @throws NullPointerException if {@code counterSig} is {@code null}
     * @throws PropertyTargetException if the property (instance) is already present
     */
    public void addCounterSignature(CounterSignatureProperty counterSig);

    /**
     * Adds a custom signed property. Multiple custom signed properties can be
     * added. The purpose of this method is extensibility.
     * <p>
     * Each custom property needs a corresponding {@link xades4j.production.PropertyDataObjectGenerator}
     * which can be supplied through {@link xades4j.production.XadesSigningProfile}.
     * 
     * @param otherSignedProp the custom property
     *
     * @throws NullPointerException if {@code otherSignedProp} is {@code null}
     * @throws PropertyTargetException if the property (instance) is already present
     * @throws IllegalArgumentException if the property is not properly annotated
     */
    public void addOtherSignatureProperty(
            OtherSignedSignatureProperty otherSignedProp);

    /**
     * Adds a custom unsigned property. Multiple custom unsigned properties can be
     * added. The purpose of this method is extensibility.
     * <p>
     * Each custom property needs a corresponding {@link xades4j.production.PropertyDataObjectGenerator}
     * which can be supplied through {@link xades4j.production.XadesSigningProfile}.
     * 
     * @param otherUnsignedProp the custom property
     * 
     * @throws NullPointerException if {@code otherUnsignedProp} is {@code null}
     * @throws PropertyTargetException if the property (instance) is already present
     * @throws IllegalArgumentException if the property is not properly annotated
     */
    public void addOtherSignatureProperty(
            OtherUnsignedSignatureProperty otherUnsignedProp);
}
