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

import java.util.Collection;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.OtherSignedSignatureProperty;
import xades4j.properties.OtherUnsignedSignatureProperty;
import xades4j.properties.SignatureProductionPlaceProperty;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.SignerRoleProperty;
import xades4j.properties.SigningTimeProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.providers.SignaturePropertiesCollector;
import xades4j.utils.PropertiesSet;

/**
 * @author Luís
 */
class SignaturePropertiesCollectorImpl implements SignaturePropertiesCollector
{
    private final PropertiesSet<SignedSignatureProperty> signedSigProps;
    private final PropertiesSet<UnsignedSignatureProperty> unsignedSigProps;

    public SignaturePropertiesCollectorImpl()
    {

        this.signedSigProps = new PropertiesSet<SignedSignatureProperty>(2);
        this.unsignedSigProps = new PropertiesSet<UnsignedSignatureProperty>(0);
    }

    /***** Signed signature properties *****/
    @Override
    public void setSigningTime(SigningTimeProperty sigTime)
    {
        signedSigProps.put(sigTime);
    }

    @Override
    public void setSignatureProductionPlace(
            SignatureProductionPlaceProperty sigProdPlace)
    {
        signedSigProps.put(sigProdPlace);
    }

    @Override
    public void setSignerRole(SignerRoleProperty signerRole)
    {
        signedSigProps.put(signerRole);
    }

    @Override
    public void addOtherSignatureProperty(
            OtherSignedSignatureProperty otherSignedSigProp)
    {
        signedSigProps.add(otherSignedSigProp);
    }

    Collection<SignedSignatureProperty> getSignedSigProps()
    {
        return signedSigProps.getProperties();
    }

    /***** Unsigned signature properties *****/
    @Override
    public void addCounterSignature(CounterSignatureProperty counterSig)
    {
        unsignedSigProps.add(counterSig);
    }

    @Override
    public void addOtherSignatureProperty(
            OtherUnsignedSignatureProperty otherUnsignedSigProp)
    {
        unsignedSigProps.add(otherUnsignedSigProp);
    }

    Collection<UnsignedSignatureProperty> getUnsignedSigProps()
    {
        return unsignedSigProps.getProperties();
    }
}
