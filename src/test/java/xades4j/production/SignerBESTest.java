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

import xades4j.properties.DataObjectTransform;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.DataObjectFormatProperty;
import org.apache.xml.security.transforms.Transforms;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.SignerRoleProperty;
import xades4j.providers.SignaturePropertiesCollector;
import xades4j.providers.SignaturePropertiesProvider;

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

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();
        SignerBES signer = (SignerBES)new XadesBesSigningProfile(keyingProviderMy).newSigner();

        IndividualDataObjsTimeStampProperty dataObjsTimeStamp = new IndividualDataObjsTimeStampProperty();
        AllDataObjsCommitmentTypeProperty globalCommitment = AllDataObjsCommitmentTypeProperty.proofOfApproval();
        CommitmentTypeProperty commitment = CommitmentTypeProperty.proofOfCreation();

        DataObjectDesc obj1 = new DataObjectReference('#' + elemToSign.getAttribute("Id")).withTransform(new DataObjectTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE)).withDataObjectFormat(new DataObjectFormatProperty("text/xml", "MyEncoding").withDescription("Isto é uma descrição do elemento raiz").withDocumentationUri("http://doc1.txt").withDocumentationUri("http://doc2.txt").withIdentifier("http://elem.root")).withCommitmentType(commitment).withDataObjectTimeStamp(dataObjsTimeStamp);
        DataObjectDesc obj2 = new EnvelopedXmlObject(doc.createElement("ElemInObject"), "text/xml", null).withDataObjectFormat(new DataObjectFormatProperty("text/xml", "MyEncoding").withDescription("Isto é uma descrição do elemento dentro do object").withDocumentationUri("http://doc3.txt").withDocumentationUri("http://doc4.txt").withIdentifier("http://elem.in.object")).withCommitmentType(commitment).withDataObjectTimeStamp(dataObjsTimeStamp);
        SignedDataObjects dataObjs = new SignedDataObjects(obj1, obj2).withCommitmentType(globalCommitment).withDataObjectsTimeStamp();

        signer.sign(dataObjs, elemToSign);

        outputDocument(doc, "document.signed.bes.xml");
    }

    @Test
    public void testSignBESExtrnlRes() throws Exception
    {
        System.out.println("signBESExtrnlRes");

        Document doc = getNewDocument();
        SignerBES signer = (SignerBES)new XadesBesSigningProfile(keyingProviderNist).newSigner();

        DataObjectDesc obj1 = new DataObjectReference("http://www.ietf.org/rfc/rfc3161.txt").withDataObjectFormat(new DataObjectFormatProperty("text/plain").withDescription("Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)")).withDataObjectTimeStamp(new IndividualDataObjsTimeStampProperty());
        signer.sign(new SignedDataObjects(obj1), doc);

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

        DataObjectDesc obj1 = new DataObjectReference('#' + elemToSign.getAttribute("Id")).withTransform(new DataObjectTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE));
        SignedDataObjects dataObjs = new SignedDataObjects().withSignedDataObject(obj1);

        signer.sign(dataObjs, elemToSign);

        outputDocument(doc, "document.signed.bes.cs.xml");
    }
}
