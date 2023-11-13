package xades4j.xml.marshalling.algorithms;

import org.apache.xml.security.utils.Constants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.algorithms.XPathTransform;
import xades4j.utils.SignatureServicesTestBase;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author Luís
 */
class XPathTransformParamsMarshallerTest
{
    private Document doc;
    private XPathTransformParamsMarshaller sut;

    @BeforeEach
    public void setUp() throws Exception
    {
        doc = SignatureServicesTestBase.getNewDocument();
        sut = new XPathTransformParamsMarshaller();
    }

    @Test
    void testMarshalXPathParametersWithNamespacePrefixes() throws Exception
    {
        XPathTransform xpath = new XPathTransform("foo:elem1/bar:elem2")
                .withNamespace("foo", "http://test.xades4j/ns1")
                .withNamespace("bar", "http://test.xades4j/ns2");

        List<Node> params = sut.marshalParameters(xpath, doc);
        assertEquals(1, params.size());
        Element paramNode = (Element) params.get(0);

        Map<String, String> namespaces = xpath.getNamespaces();

        for (Map.Entry<String, String> entry : namespaces.entrySet())
        {
            String ns = paramNode.getAttributeNS(Constants.NamespaceSpecNS, entry.getKey());
            assertNotNull(ns);
            assertFalse(ns.isEmpty());
            assertEquals(entry.getValue(), ns);
        }
    }
}
