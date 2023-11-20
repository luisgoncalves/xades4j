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

import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.algorithms.XPathTransform;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.SignerRoleProperty;

import java.io.File;

/**
 * @author Luís
 */
class SignerBESTest extends SignerTestBase
{
    public SignerBESTest()
    {
    }

    @Test
    void testSignBES() throws Exception
    {
        Document doc1 = getTestDocument();
        Document doc2 = getDocument("content.xml");
        Node objectContent = doc1.importNode(doc2.getDocumentElement(), true);
        Element elemToSign = doc1.getDocumentElement();
        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMy).with(DEFAULT_TEST_TSA).newSigner();

        IndividualDataObjsTimeStampProperty dataObjsTimeStamp = new IndividualDataObjsTimeStampProperty();
        AllDataObjsCommitmentTypeProperty globalCommitment = AllDataObjsCommitmentTypeProperty.proofOfApproval();
        CommitmentTypeProperty commitment = (CommitmentTypeProperty) CommitmentTypeProperty.proofOfCreation().withQualifier("MyQualifier");
        DataObjectDesc obj1 = new DataObjectReference('#' + elemToSign.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform()).withDataObjectFormat(new DataObjectFormatProperty("text/xml", "MyEncoding").withDescription("Isto é uma descrição do elemento raiz").withDocumentationUri("http://doc1.txt").withDocumentationUri("http://doc2.txt").withIdentifier("http://elem.root")).withCommitmentType(commitment).withDataObjectTimeStamp(dataObjsTimeStamp);
        DataObjectDesc obj2 = new EnvelopedXmlObject(objectContent, "text/xml", null).withDataObjectFormat(new DataObjectFormatProperty("text/xml", "MyEncoding").withDescription("Isto é uma descrição do elemento dentro do object").withDocumentationUri("http://doc3.txt").withDocumentationUri("http://doc4.txt").withIdentifier("http://elem.in.object")).withCommitmentType(commitment).withDataObjectTimeStamp(dataObjsTimeStamp);
        SignedDataObjects dataObjs = new SignedDataObjects(obj1, obj2).withCommitmentType(globalCommitment).withDataObjectsTimeStamp();

        signer.sign(dataObjs, elemToSign);

        outputDocument(doc1, "document.signed.bes.xml");
    }

    @Test
    void testSignBESWithEllipticCurveKey() throws Exception
    {
        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMyEc)
                .withBasicSignatureOptions(new BasicSignatureOptions().includePublicKey(true))
                .newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.bes.ec.xml");
    }

    @Test
    void testSignBESExternalRes() throws Exception
    {
        Document doc = getNewDocument();
        XadesSigner signer = new XadesBesSigningProfile(keyingProviderNist).with(DEFAULT_TEST_TSA).newSigner();

        DataObjectDesc obj1 = new DataObjectReference("logo-01.png")
                .withDataObjectFormat(new DataObjectFormatProperty("image/png").withDescription("XAdES4j logo"))
                .withDataObjectTimeStamp(new IndividualDataObjsTimeStampProperty());
        signer.sign(new SignedDataObjects(obj1)
                        .withBaseUri("http://luisgoncalves.github.io/xades4j/images/")
                        .withResourceResolver(new ResolverDirectHTTP()),
                doc);

        outputDocument(doc, "document.signed.bes.extres.xml");
    }

    @Test
    void testSignBESWithCounterSig() throws Exception
    {
        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        XadesBesSigningProfile profile = new XadesBesSigningProfile(keyingProviderMy);
        final XadesSigner counterSigner = profile.newSigner();
        profile.withSignaturePropertiesProvider(signedPropsCol -> {
            signedPropsCol.addCounterSignature(new CounterSignatureProperty(counterSigner));
            signedPropsCol.setSignerRole(new SignerRoleProperty("CounterSignature maniac"));
        });
        XadesSigner signer = profile.newSigner();

        DataObjectDesc obj1 = new DataObjectReference('#' + elemToSign.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects dataObjs = new SignedDataObjects().withSignedDataObject(obj1);

        signer.sign(dataObjs, elemToSign);

        outputDocument(doc, "document.signed.bes.cs.xml");
    }

    @Test
    void testSignBESDetachedWithXPathAndNamespaces() throws Exception
    {
        Document doc = getNewDocument();

        XadesSigner signer = new XadesBesSigningProfile(keyingProviderMy)
                .withBasicSignatureOptions(new BasicSignatureOptions()
                        .includeSigningCertificate(SigningCertificateMode.SIGNING_CERTIFICATE)
                        .includeIssuerSerial(true)
                        .includeSubjectName(true)
                        .signKeyInfo(true))
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

        SignedDataObjects objs = new SignedDataObjects(obj1, obj2)
                .withBaseUri(new File("src/test/xml/").toURI().toString())
                .withResourceResolver(new ResolverLocalFilesystem());
        signer.sign(objs, doc);

        outputDocument(doc, "detached.bes.xml");
    }
}
