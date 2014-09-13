/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package xades4j.xml.marshalling.algorithms;

import java.util.List;
import java.util.Map;
import org.apache.xml.security.utils.Constants;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.algorithms.XPathTransform;
import xades4j.utils.SignatureServicesTestBase;

/**
 *
 * @author Luís
 */
public class XPathTransformParamsMarshallerTest {

    private Document doc;
    private XPathTransformParamsMarshaller sut;

    @Before
    public void setUp() throws Exception
    {
        doc = SignatureServicesTestBase.getNewDocument();
        sut = new XPathTransformParamsMarshaller();
    }

    @Test
    public void testMarshalXPathParametersWithNamespacePrefixes() throws Exception 
    {
        XPathTransform xpath = new XPathTransform("foo:elem1/bar:elem2")
                .withNamespace("foo", "http://test.xades4j/ns1")
                .withNamespace("bar", "http://test.xades4j/ns2");

        List<Node> params = sut.marshalParameters(xpath, doc);
        assertEquals(1, params.size());
        Element paramNode = (Element) params.get(0);

        Map<String, String> namespaces = xpath.getNamespaces();

        for (Map.Entry<String, String> entry : namespaces.entrySet()) {
            String ns = paramNode.getAttributeNS(Constants.NamespaceSpecNS, entry.getKey());
            assertNotNull(ns);
            assertFalse(ns.isEmpty());
            assertEquals(entry.getValue(), ns);
        }
    }
}
