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
package xades4j.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author Luís
 */
public class SignatureServicesTestBase
{

    static private DocumentBuilder db;

    static
    {
        try
        {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            db = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException ex)
        {
            throw new NullPointerException("SignatureServicesTestBase init failed:" + ex.getMessage());
        }
    }

    public static String toPlatformSpecificFilePath(String path)
    {
        return path.replace('/', File.separatorChar);
    }

    public static String toPlatformSpecificXMLDirFilePath(String fileName)
    {
        return toPlatformSpecificFilePath("./src/test/xml/" + fileName);
    }

    public static String toPlatformSpecificCertDirFilePath(String fileName)
    {
        return toPlatformSpecificFilePath("./src/test/cert/" + fileName);
    }

    public static boolean onWindowsPlatform()
    {
        return System.getProperty("os.name").contains("Windows");
    }

    /**
     * Gets a XML document from the src/test/xml folder. If the root element of
     * the document has an "Id" attribute it is set to be its XML ID.
     */
    public static Document getDocument(String fileName) throws Exception
    {
        String path = toPlatformSpecificXMLDirFilePath(fileName);
        Document doc = db.parse(new FileInputStream(path));
        // Apache Santuario now uses Document.getElementById; use this convention for tests.
        Element elem = doc.getDocumentElement();
        DOMHelper.useIdAsXmlId(elem);
        return doc;
    }

    public static Document getNewDocument() throws Exception
    {
        return db.newDocument();
    }

    protected static void outputDocument(Document doc, String fileName) throws Exception
    {
        TransformerFactory tf = TransformerFactory.newInstance();
        File outDir = ensureOutputDir();
        FileOutputStream out = new FileOutputStream(new File(outDir, fileName));
        tf.newTransformer().transform(
                new DOMSource(doc),
                new StreamResult(out));
        out.close();
    }
    
    private static File ensureOutputDir()
    {
        File dir = new File(toPlatformSpecificFilePath("./target/out/"));
        dir.mkdir();
        return dir;
    }
}
