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

import java.util.Collections;
import java.util.List;
import org.apache.xml.security.transforms.params.InclusiveNamespaces;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.algorithms.ExclusiveCanonicalXML;
import xades4j.algorithms.ExclusiveCanonicalXMLWithComments;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;

class ExclusiveCanonicalXMLParamsMarshaller
{
    protected List<Node> doMarshal(ExclusiveCanonicalXML alg, Document doc)
    {
        InclusiveNamespaces inclusive = new InclusiveNamespaces(doc, alg.getInclusiveNamespacePrefixes());
        return Collections.singletonList((Node) inclusive.getElement());
    }
}

class ExclusiveCanonicalXMLWithCommentsParamsMarshaller
        extends ExclusiveCanonicalXMLParamsMarshaller
        implements AlgorithmParametersMarshaller<ExclusiveCanonicalXMLWithComments>
{
    @Override
    public List<Node> marshalParameters(ExclusiveCanonicalXMLWithComments alg, Document doc)
    {
        return doMarshal(alg, doc);
    }
}

class ExclusiveCanonicalXMLWithoutCommentsParamsMarshaller
        extends ExclusiveCanonicalXMLParamsMarshaller
        implements AlgorithmParametersMarshaller<ExclusiveCanonicalXMLWithoutComments>
{
    @Override
    public List<Node> marshalParameters(ExclusiveCanonicalXMLWithoutComments alg, Document doc)
    {
        return doMarshal(alg, doc);
    }
}
