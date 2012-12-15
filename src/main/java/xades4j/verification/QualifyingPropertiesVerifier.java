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
package xades4j.verification;

import java.util.Collection;
import java.util.List;

import xades4j.properties.data.CompleteCertificateRefsData;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.PropertyDataStructureException;
import xades4j.properties.data.SigningCertificateData;
import xades4j.xml.unmarshalling.QualifyingPropertiesDataCollector;

/**
 *
 * @author Luís
 */
interface QualifyingPropertiesVerifier
{
    /**
     * Verifies the data objects' structure and the XAdES rules.
     */
    List<PropertyInfo> verifyProperties(
           QualifyingPropertiesDataCollector unmarshalledProperties,
            QualifyingPropertyVerificationContext ctx) throws PropertyDataStructureException, InvalidPropertyException, QualifyingPropertyVerifierNotAvailableException;

    /**
     * Verifies the data objects' structure and the XAdES rules.
     * Use {@link QualifyingPropertiesVerifier#verifyProperties(QualifyingPropertiesDataCollector, QualifyingPropertyVerificationContext)}
     * TODO left because legacy parts of verifiers need to verify only some properties,
     * for example just SignatureTimeStamp
     */
    @Deprecated
    Collection<PropertyInfo> verifyProperties(
            List<PropertyDataObject> unmarshalledProperties,
             QualifyingPropertyVerificationContext ctx) throws PropertyDataStructureException, InvalidPropertyException, QualifyingPropertyVerifierNotAvailableException;

    /**
     * Verifies properties that can be verified only after Signature has been verified,
     * namely {@link CompleteCertificateRefsData}, {@link CompleteRevocationRefsData} and
     * {@link SigningCertificateData}.
     * @param propsDataCollector
     * @param qPropsCtx
     * @param props
     * @return
     */
    List<PropertyInfo> verifyProperties(
            HybridQualifPropsDataCollectorImpl propsDataCollector,
            QualifyingPropertyVerificationContext qPropsCtx,
            List<PropertyInfo> props);
}
