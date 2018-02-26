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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.DataObjectFormatProperty;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.algorithms.XPathTransform;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.SignerRoleProperty;
import xades4j.providers.SignaturePropertiesCollector;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.impl.DefaultBasicSignatureOptionsProvider;

/**
 *
 * @author Luís
 */
public class SignerBESTest extends SignerTestBase
{
    public SignerBESTest()
    {
    }
    
    @Test
    public void testSignBES() throws Exception
    {
        System.out.println("signBES");

        Document doc1 = getTestDocument();
        Document doc2 = getDocument("content.xml");
        Node objectContent = doc1.importNode(doc2.getDocumentElement(), true);
        Element elemToSign = doc1.getDocumentElement();
        SignerBES signer = (SignerBES)new XadesBesSigningProfile(keyingProviderMy).newSigner();

        IndividualDataObjsTimeStampProperty dataObjsTimeStamp = new IndividualDataObjsTimeStampProperty();
        AllDataObjsCommitmentTypeProperty globalCommitment = AllDataObjsCommitmentTypeProperty.proofOfApproval();
        CommitmentTypeProperty commitment = (CommitmentTypeProperty)CommitmentTypeProperty.proofOfCreation().withQualifier("MyQualifier");
        DataObjectDesc obj1 = new DataObjectReference('#' + elemToSign.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform()).withDataObjectFormat(new DataObjectFormatProperty("text/xml", "MyEncoding").withDescription("Isto é uma descrição do elemento raiz").withDocumentationUri("http://doc1.txt").withDocumentationUri("http://doc2.txt").withIdentifier("http://elem.root")).withCommitmentType(commitment).withDataObjectTimeStamp(dataObjsTimeStamp);
        DataObjectDesc obj2 = new EnvelopedXmlObject(objectContent, "text/xml", null).withDataObjectFormat(new DataObjectFormatProperty("text/xml", "MyEncoding").withDescription("Isto é uma descrição do elemento dentro do object").withDocumentationUri("http://doc3.txt").withDocumentationUri("http://doc4.txt").withIdentifier("http://elem.in.object")).withCommitmentType(commitment).withDataObjectTimeStamp(dataObjsTimeStamp);
        SignedDataObjects dataObjs = new SignedDataObjects(obj1, obj2).withCommitmentType(globalCommitment).withDataObjectsTimeStamp();

        signer.sign(dataObjs, elemToSign);

        outputDocument(doc1, "document.signed.bes.xml");
    }

    @Test
    public void testSignBESExtrnlRes() throws Exception
    {
        System.out.println("signBESExtrnlRes");

        Document doc = getNewDocument();
        SignerBES signer = (SignerBES)new XadesBesSigningProfile(keyingProviderNist).newSigner();

        DataObjectDesc obj1 = new DataObjectReference("rfc3161.txt").withDataObjectFormat(new DataObjectFormatProperty("text/plain").withDescription("Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)")).withDataObjectTimeStamp(new IndividualDataObjsTimeStampProperty());
        signer.sign(new SignedDataObjects(obj1).withBaseUri("http://www.ietf.org/rfc/"), doc);

        outputDocument(doc, "document.signed.bes.extres.xml");
    }

    @Test
    public void testSignBESWithCounterSig() throws Exception
    {
        System.out.println("signBESWithCounterSig");

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        XadesBesSigningProfile profile = new XadesBesSigningProfile(keyingProviderMy);
        final XadesSigner counterSigner = profile.newSigner();
        profile.withSignaturePropertiesProvider(new SignaturePropertiesProvider()
        {
            @Override
            public void provideProperties(
                    SignaturePropertiesCollector signedPropsCol)
            {
                signedPropsCol.addCounterSignature(new CounterSignatureProperty(counterSigner));
                signedPropsCol.setSignerRole(new SignerRoleProperty("CounterSignature maniac"));
            }
        });
        SignerBES signer = (SignerBES)profile.newSigner();

        DataObjectDesc obj1 = new DataObjectReference('#' + elemToSign.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects dataObjs = new SignedDataObjects().withSignedDataObject(obj1);

        signer.sign(dataObjs, elemToSign);

        outputDocument(doc, "document.signed.bes.cs.xml");
    }
    
    public static class MyBasicSignatureOptionsProvider extends DefaultBasicSignatureOptionsProvider{
        @Override
        public boolean signSigningCertificate() {
            return true;
        }
    }
    
    @Test
    public void testSignBESDetachedWithXPathAndNamespaces() throws Exception
    {
        System.out.println("signBESDetachedWithXPathAndNamespaces");
        
        Document doc = getNewDocument();
        
        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMy)
                .withBasicSignatureOptionsProvider(MyBasicSignatureOptionsProvider.class)
                .newSigner();
        
        DataObjectDesc obj1 = new DataObjectReference("document.xml")
                .withTransform(
                    new XPathTransform("/collection/album/foo:tracks")
                        .withNamespace("foo", "http://test.xades4j/tracks"))
                .withDataObjectFormat(new DataObjectFormatProperty("text/xml"));
        
        DataObjectDesc obj2 = new DataObjectReference("document.xml")
                .withTransform(
                    XPath2Filter.intersect("/collection/album/bar:tracks/bar:song[@tracknumber = 1]")
                        .withNamespace("bar", "http://test.xades4j/tracks"));
        
        SignedDataObjects objs = new SignedDataObjects(obj1, obj2).withBaseUri(new File("src/test/xml/").toURI().toString());
        signer.sign(objs, doc);
        
        outputDocument(doc, "detached.bes.xml");
    }

}
