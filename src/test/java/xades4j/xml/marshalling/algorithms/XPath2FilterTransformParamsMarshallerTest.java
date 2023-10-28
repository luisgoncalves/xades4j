package xades4j.xml.marshalling.algorithms;

import org.apache.xml.security.utils.Constants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.algorithms.XPath2FilterTransform;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.utils.SignatureServicesTestBase;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 *
 * @author Luís
 */
public class XPath2FilterTransformParamsMarshallerTest {

    private Document doc;
    private XPath2FilterTransformParamsMarshaller sut;

    @BeforeEach
    public void setUp() throws Exception {
        doc = SignatureServicesTestBase.getNewDocument();
        sut = new XPath2FilterTransformParamsMarshaller();
    }

    @Test
    public void testMarshalXPathParametersWithNamespacePrefixes() throws Exception {
        XPath2FilterTransform xpath = XPath2Filter
                .intersect("foo:elem1")
                .union("bar:elem2")
                .withNamespace("foo", "http://test.xades4j/ns1")
                .withNamespace("bar", "http://test.xades4j/ns2");

        List<Node> params = sut.marshalParameters(xpath, doc);
        assertEquals(2, params.size());

        Set<Map.Entry<String, String>> namespaces = xpath.getNamespaces().entrySet();

        for (Node paramNode : params) 
        {
            for (Map.Entry<String, String> entry : namespaces) 
            {
                String ns = ((Element)paramNode).getAttributeNS(Constants.NamespaceSpecNS, entry.getKey());
                assertNotNull(ns);
                assertFalse(ns.isEmpty());
                assertEquals(entry.getValue(), ns);
            }
        }
    }
}
