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

import com.google.inject.Inject;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.XAdES4jException;
import xades4j.providers.AlgorithmsProvider;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.ValidationData;
import xades4j.providers.ValidationDataException;
import xades4j.providers.ValidationDataProvider;
import xades4j.utils.PropertiesUtils;
import xades4j.xml.marshalling.SignedPropertiesMarshaller;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;

/**
 * Produces XAdES-C signatures.
 * @author Luís
 */
class SignerC extends SignerT
{
    private final ValidationDataProvider validationDataProvider;

    @Inject
    protected SignerC(KeyingDataProvider keyingProvider,
            SignaturePropertiesProvider signaturePropsProvider,
            ValidationDataProvider validationDataProvider,
            DataObjectPropertiesProvider dataObjPropsProvider,
            PropertiesDataObjectsGenerator propsDataObjectsGenerator,
            AlgorithmsProvider algorithmsProvider,
            SignedPropertiesMarshaller signedPropsMarshaller,
            UnsignedPropertiesMarshaller unsignedPropsMarshaller)
    {
        super(keyingProvider, signaturePropsProvider, dataObjPropsProvider, propsDataObjectsGenerator, algorithmsProvider, signedPropsMarshaller, unsignedPropsMarshaller);
        if (null == validationDataProvider)
            throw new NullPointerException("ValidationDataProvider is null");

        this.validationDataProvider = validationDataProvider;
    }

    @Override
    protected void getFormatSpecificSignatureProperties(
            Collection<SignedSignatureProperty> formatSpecificSignedSigProps,
            Collection<UnsignedSignatureProperty> formatSpecificUnsignedSigProps,
            List<X509Certificate> signingCertificateChain) throws XAdES4jException
    {
        super.getFormatSpecificSignatureProperties(formatSpecificSignedSigProps, formatSpecificUnsignedSigProps, signingCertificateChain);

        ValidationData vData = this.validationDataProvider.getValidationData(signingCertificateChain);
        if (null == vData)
            throw new ValidationDataException("Validation data not provided");

        PropertiesUtils.addXadesCProperties(formatSpecificUnsignedSigProps, vData);
    }
}
