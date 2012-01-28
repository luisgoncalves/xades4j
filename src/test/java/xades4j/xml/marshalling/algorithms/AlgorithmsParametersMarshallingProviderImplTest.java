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

import org.w3c.dom.Node;
import java.util.List;
import xades4j.algorithms.*;
import com.google.inject.Injector;
import com.google.inject.Guice;
import org.w3c.dom.Document;
import xades4j.utils.SignatureServicesTestBase;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class AlgorithmsParametersMarshallingProviderImplTest
{

    @Test
    public void testMarshalParameters() throws Exception
    {
        Document doc = SignatureServicesTestBase.getNewDocument();
        Injector injector = Guice.createInjector(new AlgorithmParametersBindingsModule());

        AlgorithmsParametersMarshallingProviderImpl instance = new AlgorithmsParametersMarshallingProviderImpl(injector);

        Algorithm[] algorithms = new Algorithm[]
        {
            new XPathTransform("xpath"),
            new ExclusiveCanonicalXMLWithComments("ds foo bar"),
            new GenericAlgorithm("uri", doc.createElement("param1"), doc.createElement("param2"))
        };

        for (Algorithm alg : algorithms)
        {
            List<Node> params = instance.marshalParameters(alg, doc);
            assertNotNull(params);
        }

        algorithms = new Algorithm[]
        {
            new EnvelopedSignatureTransform(),
            new CanonicalXMLWithoutComments(),
            new GenericAlgorithm("uri")
        };

        for (Algorithm t : algorithms)
        {
            List<Node> params = instance.marshalParameters(t, doc);
            assertNull(params);
        }
    }
}
