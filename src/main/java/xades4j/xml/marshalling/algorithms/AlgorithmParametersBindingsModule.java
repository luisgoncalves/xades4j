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
import com.google.inject.multibindings.MapBinder;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.algorithms.*;
import xades4j.properties.DataObjectTransform;

import javax.annotation.Nullable;
import java.util.List;

/**
 * Contains the Guice bindings for the components on this package.
 *
 * @author Luís
 */
public final class AlgorithmParametersBindingsModule extends AbstractModule
{
    @Override
    protected void configure()
    {
        bind(AlgorithmsParametersMarshallingProvider.class).to(AlgorithmsParametersMarshallingProviderImpl.class);

        // Algorithms with parameters

        bindMarshaller(XPath2FilterTransform.class, XPath2FilterTransformParamsMarshaller.class);
        bindMarshaller(XPathTransform.class, XPathTransformParamsMarshaller.class);
        bindMarshaller(ExclusiveCanonicalXMLWithComments.class, ExclusiveCanonicalXMLWithCommentsParamsMarshaller.class);
        bindMarshaller(ExclusiveCanonicalXMLWithoutComments.class, ExclusiveCanonicalXMLWithoutCommentsParamsMarshaller.class);
        bindMarshaller(GenericAlgorithm.class, GenericAlgorithmParamsMarshaller.class);
        bindMarshaller(DataObjectTransform.class, DeprecatedDataObjectTransformParamsMarshaller.class);

        // Algorithms without parameters

        bindMarshaller(EnvelopedSignatureTransform.class, null);
        bindMarshaller(CanonicalXMLWithComments.class, null);
        bindMarshaller(CanonicalXMLWithoutComments.class, null);
    }

    private <T extends Algorithm> void bindMarshaller(
            Class<T> algorithmClass,
            @Nullable Class<? extends AlgorithmParametersMarshaller<T>> marshallerClass)
    {
        MapBinder<Class<? extends Algorithm>, AlgorithmParametersMarshaller<? extends Algorithm>> mapBinder = MapBinder.newMapBinder(
                binder(),
                new TypeLiteral<Class<? extends Algorithm>>()
                {
                },
                new TypeLiteral<AlgorithmParametersMarshaller<? extends Algorithm>>()
                {
                });

        if (marshallerClass != null)
        {
            mapBinder.addBinding(algorithmClass).to(marshallerClass);
        }
        else
        {
            mapBinder.addBinding(algorithmClass).toInstance(new AlgorithmParametersMarshaller<T>()
            {
                @Override
                public List<Node> marshalParameters(T alg, Document doc)
                {
                    return null;
                }
            });
        }
    }
}
