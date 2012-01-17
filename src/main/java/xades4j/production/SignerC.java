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

import com.google.inject.Inject;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.XAdES4jException;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.BasicSignatureOptionsProvider;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.ValidationData;
import xades4j.providers.ValidationDataException;
import xades4j.providers.ValidationDataProvider;
import xades4j.utils.PropertiesUtils;
import xades4j.xml.marshalling.SignedPropertiesMarshaller;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 * Produces XAdES-C signatures.
 * @author Luís
 */
class SignerC extends SignerT
{
    private final ValidationDataProvider validationDataProvider;

    @Inject
    protected SignerC(
            KeyingDataProvider keyingProvider,
            AlgorithmsProviderEx algorithmsProvider,
            BasicSignatureOptionsProvider basicSignatureOptionsProvider,
            DataObjectDescsProcessor dataObjectDescsProcessor,
            SignaturePropertiesProvider signaturePropsProvider,
            ValidationDataProvider validationDataProvider,
            DataObjectPropertiesProvider dataObjPropsProvider,
            PropertiesDataObjectsGenerator propsDataObjectsGenerator,
            SignedPropertiesMarshaller signedPropsMarshaller,
            UnsignedPropertiesMarshaller unsignedPropsMarshaller,
            AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller)
    {
        super(keyingProvider, algorithmsProvider, basicSignatureOptionsProvider, dataObjectDescsProcessor, signaturePropsProvider, dataObjPropsProvider, propsDataObjectsGenerator, signedPropsMarshaller, unsignedPropsMarshaller, algorithmsParametersMarshaller);
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
