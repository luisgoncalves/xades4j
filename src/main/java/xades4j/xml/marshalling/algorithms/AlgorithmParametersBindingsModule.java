/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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
package xades4j.xml.marshalling.algorithms;

import com.google.inject.AbstractModule;
import com.google.inject.TypeLiteral;
import xades4j.production.EnvelopedSignatureTransform;
import xades4j.GenericAlgorithm;
import xades4j.properties.DataObjectTransform;
import xades4j.production.XPath2FilterTransform;
import xades4j.production.XPathTransform;

/**
 * Contains the Guice bindings for the components on this package.
 * @author Luís
 */
public final class AlgorithmParametersBindingsModule extends AbstractModule
{
    @Override
    protected void configure()
    {
        bind(AlgorithmsParametersMarshallingProvider.class)
                .to(AlgorithmsParametersMarshallingProviderImpl.class);


        bind(new TypeLiteral<AlgorithmParametersMarshaller<EnvelopedSignatureTransform>>()
        {
        }).to(EnvelopedSignatureTransformParamsMarshaller.class);

        bind(new TypeLiteral<AlgorithmParametersMarshaller<XPath2FilterTransform>>()
        {
        }).to(XPath2FilterTransformParamsMarshaller.class);

        bind(new TypeLiteral<AlgorithmParametersMarshaller<XPathTransform>>()
        {
        }).to(XPathTransformParamsMarshaller.class);

        bind(new TypeLiteral<AlgorithmParametersMarshaller<GenericAlgorithm>>()
        {
        }).to(GenericAlgorithmParamsMarshaller.class);

        bind(new TypeLiteral<AlgorithmParametersMarshaller<DataObjectTransform>>()
        {
        }).to(DeprecatedDataObjectTransformParamsMarshaller.class);
    }
}
