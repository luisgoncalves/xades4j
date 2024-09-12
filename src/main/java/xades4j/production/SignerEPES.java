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

import jakarta.inject.Inject;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.ValidationDataException;
import xades4j.providers.X500NameStyleProvider;
import xades4j.utils.PropertiesUtils;
import xades4j.xml.marshalling.SignedPropertiesMarshaller;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * Produces XAdES-EPES signatures.
 *
 * @author Luís
 */
class SignerEPES extends SignerBES
{
    private final SignaturePolicyInfoProvider policyInfoProvider;
    /**/

    @Inject
    protected SignerEPES(
            KeyingDataProvider keyingProvider,
            SignatureAlgorithms signatureAlgorithms,
            BasicSignatureOptions basicSignatureOptions,
            SignedDataObjectsProcessor dataObjectDescsProcessor,
            SignaturePolicyInfoProvider policyInfoProvider,
            SignaturePropertiesProvider signaturePropsProvider,
            DataObjectPropertiesProvider dataObjPropsProvider,
            PropertiesDataObjectsGenerator propsDataObjectsGenerator,
            SignedPropertiesMarshaller signedPropsMarshaller,
            UnsignedPropertiesMarshaller unsignedPropsMarshaller,
            AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller,
            X500NameStyleProvider x500NameStyleProvider,
            ElementIdGeneratorFactory idGeneratorFactory)
    {
        super(keyingProvider, signatureAlgorithms, basicSignatureOptions, dataObjectDescsProcessor, signaturePropsProvider, dataObjPropsProvider, propsDataObjectsGenerator, signedPropsMarshaller, unsignedPropsMarshaller, algorithmsParametersMarshaller, x500NameStyleProvider, idGeneratorFactory);
        this.policyInfoProvider = policyInfoProvider;
    }

    @Override
    protected void getFormatSpecificSignatureProperties(
            Collection<SignedSignatureProperty> formatSpecificSignedSigProps,
            Collection<UnsignedSignatureProperty> formatSpecificUnsignedSigProps,
            List<X509Certificate> signingCertificateChain) throws ValidationDataException
    {
        super.getFormatSpecificSignatureProperties(formatSpecificSignedSigProps, formatSpecificUnsignedSigProps, signingCertificateChain);

        PropertiesUtils.addXadesEpesProperties(formatSpecificSignedSigProps, this.policyInfoProvider);
    }
}
