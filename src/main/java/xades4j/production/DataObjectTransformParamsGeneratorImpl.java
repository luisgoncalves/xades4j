/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.util.Types;
import java.lang.reflect.ParameterizedType;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import xades4j.xml.marshalling.transforms.DataObjectTransformParamsMarshaller;

/**
 *
 * @author Luís
 */
class DataObjectTransformParamsGeneratorImpl implements DataObjectTransformParamsGenerator
{
    private final Injector injector;

    @Inject
    public DataObjectTransformParamsGeneratorImpl(Injector injector)
    {
        this.injector = injector;
    }

    @Override
    public NodeList getParameters(DataObjectTransform t, Document doc)
    {
        try
        {
            ParameterizedType pt = Types.newParameterizedType(DataObjectTransformParamsMarshaller.class, t.getClass());
            DataObjectTransformParamsMarshaller marshaller = (DataObjectTransformParamsMarshaller) injector.getInstance(Key.get(TypeLiteral.get(pt)));
            return marshaller.marshalParameters(t, doc);
        }
        catch (RuntimeException ex)
        {
            // TODO change exception type?
            throw new UnsupportedOperationException("Params marshaller not available for: " + t.getTransformUri(), ex);
        }
    }
}
