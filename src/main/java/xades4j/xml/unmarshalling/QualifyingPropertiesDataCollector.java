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
package xades4j.xml.unmarshalling;

import xades4j.properties.data.AllDataObjsTimeStampData;
import xades4j.properties.data.SigningTimeData;
import xades4j.properties.data.SigningCertificateData;
import xades4j.properties.data.SignatureProdPlaceData;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.properties.data.CompleteCertificateRefsData;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.properties.data.GenericDOMData;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.properties.data.OtherPropertyData;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.properties.data.SignerRoleData;

/**
 * Passed to a {@link QualifyingPropertiesUnmarshaller} to collect the property
 * data obejcts. This is used instead of a collection that is returned by the unmarshaller
 * because it allows controlling the number of occurrences of each property.
 * <p>
 * All the methods will throw {@code PropertyTargetException} if an attempt is made
 * to add a repeated instance or an instance of a type that was already added and
 * should occur only once. Also, {@code NullPointerException} is thrown if an attempt
 * is made to add a {@code null} reference.
 * @author Luís
 */
public interface QualifyingPropertiesDataCollector
{
    public void setSigningTime(SigningTimeData sigTimeData);

    public void setSignatureProdPlace(SignatureProdPlaceData sigProdPlaceData);

    public void setSignerRole(SignerRoleData signerRoleData);

    public void setSigningCertificate(SigningCertificateData signingCertData);

    public void setSignaturePolicy(SignaturePolicyData sigPolicyData);

    public void setCompleteCertificateRefs(
            CompleteCertificateRefsData completeCertRefsData);

    public void setCompleteRevocRefs(
            CompleteRevocationRefsData completeRecovRefsData);

    public void addSignatureTimeStamp(SignatureTimeStampData sigTSData);

    public void addCommitmentType(CommitmentTypeData commitmentData);

    public void addDataObjectFormat(DataObjectFormatData formatData);

    public void addAllDataObjsTimeStamp(AllDataObjsTimeStampData objsTSData);

    public void addIndividualDataObjsTimeStamp(
            IndividualDataObjsTimeStampData objsTSData);

    public void addGenericDOMData(GenericDOMData domData);

    public void addOther(OtherPropertyData otherData);
}
