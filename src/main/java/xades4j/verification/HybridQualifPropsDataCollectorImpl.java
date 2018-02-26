/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
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
package xades4j.verification;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import xades4j.properties.data.AllDataObjsTimeStampData;
import xades4j.properties.data.ArchiveTimeStampData;
import xades4j.properties.data.AttrAuthoritiesCertValuesData;
import xades4j.properties.data.AttributeRevocationValuesData;
import xades4j.properties.data.CertificateValuesData;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.properties.data.CompleteCertificateRefsData;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.properties.data.GenericDOMData;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.properties.data.OtherPropertyData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.RevocationValuesData;
import xades4j.properties.data.SigAndRefsTimeStampData;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.properties.data.SignatureProdPlaceData;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.properties.data.SignerRoleData;
import xades4j.properties.data.SigningCertificateData;
import xades4j.properties.data.SigningTimeData;
import xades4j.properties.data.TimeStampValidationDataData;
import xades4j.utils.PropertiesList;
import xades4j.utils.PropertiesSet;
import xades4j.xml.unmarshalling.QualifyingPropertiesDataCollector;

public class HybridQualifPropsDataCollectorImpl implements
        QualifyingPropertiesDataCollector
{
    private final PropertiesSet<PropertyDataObject> signedSigProperties;
    private final PropertiesSet<PropertyDataObject> signedDataObjectProperties;
    private final PropertiesList<PropertyDataObject> unsignedSigProperties;
    private final PropertiesList<PropertyDataObject> unsignedDataObjectProperties;
    private final List<Element> unsignedSigPropertiesElements;

    public HybridQualifPropsDataCollectorImpl()
    {
        signedSigProperties = new PropertiesSet<PropertyDataObject>(1);
        signedDataObjectProperties = new PropertiesSet<PropertyDataObject>(1);
        unsignedSigProperties = new PropertiesList<PropertyDataObject>(1);
        unsignedDataObjectProperties = new PropertiesList<PropertyDataObject>(1);
        unsignedSigPropertiesElements = new ArrayList<Element>();
    }

    @Override
    public void setSigningTime(SigningTimeData sigTimeData)
    {
        signedSigProperties.put(sigTimeData);
    }

    @Override
    public void setSignatureProdPlace(SignatureProdPlaceData sigProdPlaceData)
    {
        signedSigProperties.put(sigProdPlaceData);
    }

    @Override
    public void setSignerRole(SignerRoleData signerRoleData)
    {
        signedSigProperties.put(signerRoleData);
    }

    @Override
    public void setSigningCertificate(SigningCertificateData signingCertData)
    {
        signedSigProperties.put(signingCertData);
    }

    @Override
    public void setSignaturePolicy(SignaturePolicyData sigPolicyData)
    {
        signedSigProperties.put(sigPolicyData);
    }

    @Override
    public void setCompleteCertificateRefs(
            CompleteCertificateRefsData completeCertRefsData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.put(completeCertRefsData);
    }

    @Override
    public void setCompleteRevocRefs(
            CompleteRevocationRefsData completeRecovRefsData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.put(completeRecovRefsData);
    }

    @Override
    public void addSignatureTimeStamp(SignatureTimeStampData sigTSData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.add(sigTSData);
    }

    @Override
    public void addCommitmentType(CommitmentTypeData commitmentData)
    {
        signedDataObjectProperties.add(commitmentData);
    }

    @Override
    public void addDataObjectFormat(DataObjectFormatData formatData)
    {
        signedDataObjectProperties.add(formatData);
    }

    @Override
    public void addAllDataObjsTimeStamp(AllDataObjsTimeStampData objsTSData)
    {
        signedDataObjectProperties.add(objsTSData);
    }

    @Override
    public void addIndividualDataObjsTimeStamp(
            IndividualDataObjsTimeStampData objsTSData)
    {
        signedDataObjectProperties.add(objsTSData);
    }

    @Override
    public void addGenericDOMData(GenericDOMData domData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.add(domData);
    }

    @Override
    public void addOther(OtherPropertyData otherData)
    {
        unsignedDataObjectProperties.add(otherData);
    }

    @Override
    public void addSigAndRefsTimeStamp(SigAndRefsTimeStampData tsData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.add(tsData);
    }

    @Override
    public void setCertificateValues(CertificateValuesData certificateValuesData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.put(certificateValuesData);
    }

    @Override
    public void setRevocationValues(RevocationValuesData revocationValuesData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.put(revocationValuesData);
    }

    @Override
    public void setAttrAuthoritiesCertValues(
            AttrAuthoritiesCertValuesData attrAuthoritiesCertValuesData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.put(attrAuthoritiesCertValuesData);
    }

    @Override
    public void setAttributeRevocationValues(
            AttributeRevocationValuesData attrRevocValData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.put(attrRevocValData);
    }

    @Override
    public void addArchiveTimeStamp(ArchiveTimeStampData tsData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property!");

        unsignedSigProperties.add(tsData);
    }

    @Override
    public void addTimeStampValidationDataData(
            TimeStampValidationDataData timeStampValidationDataData)
    {
        if (unsignedSigProperties.size() != unsignedSigPropertiesElements.size())
            throw new IllegalStateException("No Element linked to previous property");

        unsignedSigProperties.add(timeStampValidationDataData);
    }

    List<PropertyDataObject> getUnsignedPropertiesData()
    {
        return unsignedSigProperties.getProperties();
    }

    @Override
    public List<PropertyDataObject> getPropertiesData()
    {
        List<PropertyDataObject> ret = new ArrayList<PropertyDataObject>();
        ret.addAll(signedSigProperties.getProperties());
        ret.addAll(signedDataObjectProperties.getProperties());
        ret.addAll(unsignedSigProperties.getProperties());
        ret.addAll(unsignedDataObjectProperties.getProperties());
        return ret;
    }

    @Override
    public void linkPropertyToElem(Element node)
    {
        unsignedSigPropertiesElements.add(node);
    }

    @Override
    public Node getPropertyNode(PropertyDataObject pdo)
    {
        int index = unsignedSigProperties.getProperties().indexOf(pdo);
        if (index == -1)
            return null;

        return unsignedSigPropertiesElements.get(index);
    }
}
