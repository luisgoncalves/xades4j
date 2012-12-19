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
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;

import org.w3c.dom.Element;

import com.google.inject.Inject;

import xades4j.XAdES4jException;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.data.AllDataObjsTimeStampData;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.properties.data.CompleteCertificateRefsData;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.properties.data.PropertiesDataObjectsStructureVerifier;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.PropertyDataStructureException;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.properties.data.SignatureProdPlaceData;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.properties.data.SignerRoleData;
import xades4j.properties.data.SigningCertificateData;
import xades4j.properties.data.SigningTimeData;
import xades4j.xml.unmarshalling.QualifyingPropertiesDataCollector;

public class HybridQualifyingPropertiesVerifierImpl implements
        QualifyingPropertiesVerifier
{
    private final QualifyingPropertyVerifiersMapper propertyVerifiersMapper;
    private final PropertiesDataObjectsStructureVerifier dataObjectsStructureVerifier;
    private final Set<Class<?>> sigAndRefsPropertySignedProperties;
    private final Set<Class<?>> signedProperties;

    @Inject
    public HybridQualifyingPropertiesVerifierImpl(
            QualifyingPropertyVerifiersMapper propVerMapp,
            PropertiesDataObjectsStructureVerifier dataObjStructVerif)
    {
        propertyVerifiersMapper = propVerMapp;
        dataObjectsStructureVerifier = dataObjStructVerif;
        Set<Class<?>> tmp = new HashSet<Class<?>>();
        // TODO tmp.add(AttributeRevocationRefsData.class);
        // TODO tmp.add(AttributeCertificateRefsData.class);
        tmp.add(CompleteRevocationRefsData.class);
        tmp.add(CompleteCertificateRefsData.class);
        tmp.add(SignatureTimeStampData.class);
        sigAndRefsPropertySignedProperties = tmp;

        tmp = new HashSet<Class<?>>();
        tmp.add(IndividualDataObjsTimeStampData.class);
        tmp.add(AllDataObjsTimeStampData.class);
        tmp.add(CommitmentTypeData.class);
        tmp.add(DataObjectFormatData.class);
        tmp.add(SignerRoleData.class);
        tmp.add(SignatureProdPlaceData.class);
        tmp.add(SignaturePolicyData.class);
        tmp.add(SigningCertificateData.class);
        tmp.add(SigningTimeData.class);
        signedProperties = tmp;
    }

    /*
     * new invocation method (one that knows about XML structure of properties)
     */
    @Override
    public List<PropertyInfo> verifyProperties(
            QualifyingPropertiesDataCollector dataCollector,
            QualifyingPropertyVerificationContext ctx)
            throws PropertyDataStructureException, InvalidPropertyException,
            QualifyingPropertyVerifierNotAvailableException
    {
        // verify internal data structure of properties (presence of mandatory elements
        // and sanity of all elements)
        List<PropertyDataObject> unmarshalledProperties = dataCollector.getPropertiesData();
        dataObjectsStructureVerifier.verifiyPropertiesDataStructure(unmarshalledProperties);

        List<PropertyInfo> props = new LinkedList<PropertyInfo>();

        /*
         * go over all properties and verify them
         * because the most recent additions to the signature are (or at least SHOULD be)
         * last, we go in reverse order
         */
        ListIterator<PropertyDataObject> property =
                unmarshalledProperties.listIterator(unmarshalledProperties.size());

        PropertyDataObject propData;
        do
        {
            propData = property.previous();
            /*
             * Because ArchiveTimeStamp signs everything before its location, we update
             * the currentTime in ctx just after its successful verification.
             * This is not so easy with SignatureTimeStamp or SigAndRefsTimeStamp, there
             * we can update the currentTime only after we went over all those
             * properties, that is, we found the first property that should have been
             * signed by SigAndRefsTimeStamp.
             *
             * With SignatureTimeStamp similar situation occurs when there are only
             * SignedProperties left or all properties have been handled
             *
             * TODO The situation is even more complex in the unsupported case of
             * RefsOnlyTimeStamp.
             *
             * TODO handle gracefully multiple ArchiveTimeStamps with similar times
             * The above described behavior may cause failure of verification for one
             * of the ArchiveTimeStamps if there are multiple ArchiveTimeStamps present,
             * but it won't cause failure in verification of the whole signature.
             * If the first ArchiveTimeStamp is invalid, it won't change the time, so the
             * second one will verify successfully.
             */
            try {
                // when we encounter property that needs to be signed by
                // sigAndRefsTimeStamp it means we should have parsed all
                // SigAndRefsTimeStamps and can change time to the earliest one from
                // those properties
                if (sigAndRefsPropertySignedProperties.contains(propData.getClass()))
                    setDateFromSigAndRefsProperty(ctx, props);
                // similar situation as with sigAndRefsTimeStamp but for SignatureTimeStamp
                if (signedProperties.contains(propData.getClass()))
                    setDateFromSignatureTimeStamp(ctx, props);
                // verificator of ArchiveTimeStamp changes time itself

                /*
                 * To verify those three properties we need result of Signature
                 * verification, so we add place holders for them and will verify them
                 * after Signature verification
                 */
                if (propData instanceof CompleteCertificateRefsData ||
                    propData instanceof CompleteRevocationRefsData ||
                    propData instanceof SigningCertificateData)
                {
                    props.add(0, new PropertyInfo(propData, null));
                    continue;
                }

                QualifyingPropertyVerifier<PropertyDataObject> propVerifier =
                        this.propertyVerifiersMapper.getVerifier(propData);

                Element elem = (Element) dataCollector.getPropertyNode(propData);

                QualifyingProperty p = propVerifier.verify(propData, elem, ctx);
                if (p == null)
                        throw new PropertyVerifierErrorException(propData
                            .getClass().getName());

                // we go over properties in reverse order so we have to insert
                // them at the beginning of the returned list to preserve order
                props.add(0, new PropertyInfo(propData, p));

            } catch (XAdES4jException e) // TODO make it less generic
            {
                // critical error
                if (e instanceof SigningTimeVerificationException)
                    throw (InvalidPropertyException)e;

                // failure in verification of property will only cause its ommitance
                // in returned property list
                System.out.println("Error when verifying " + propData.getClass()
                        + ", stack trace follows: ");
                e.printStackTrace();
                continue;
            }

        } while (property.hasPrevious());

        // SignedProperties are not mandatory so we have to try changing the time after
        // parsing all properties
        setDateFromSignatureTimeStamp(ctx, props);

        return Collections.unmodifiableList(props);
    }

    private void setDateFromSignatureTimeStamp(
            QualifyingPropertyVerificationContext ctx,
            List<PropertyInfo> props)
    {
        Date oldest = null;
        for (PropertyInfo propInfo : props)
        {
            QualifyingProperty p = propInfo.getProperty();
            if (p instanceof SignatureTimeStampProperty)
            {
                SignatureTimeStampProperty sigTimeStamp = (SignatureTimeStampProperty) p;
                if (oldest == null)
                    oldest = sigTimeStamp.getTime();
                else if (oldest.getTime() > sigTimeStamp.getTime().getTime())
                    oldest = sigTimeStamp.getTime();
            }
        }
        if (oldest != null && oldest.getTime() != ctx.getCurrentTime().getTime())
            ctx.setCurrentTime(oldest);
    }

    private void setDateFromSigAndRefsProperty(
            QualifyingPropertyVerificationContext ctx,
            List<PropertyInfo> props)
    {
        Date oldest = null;
        for (PropertyInfo propInfo : props)
        {
            QualifyingProperty p = propInfo.getProperty();
            if (p instanceof SigAndRefsTimeStampProperty)
            {
                SigAndRefsTimeStampProperty sigAndRefs = (SigAndRefsTimeStampProperty) p;
                if (oldest == null)
                    oldest = sigAndRefs.getTime();
                else if (oldest.getTime() > sigAndRefs.getTime().getTime())
                    oldest = sigAndRefs.getTime();
            }
        }

        if (oldest != null && oldest.getTime() != ctx.getCurrentTime().getTime())
            ctx.setCurrentTime(oldest);
    }

    @Deprecated
    @Override
    public Collection<PropertyInfo> verifyProperties(
            List<PropertyDataObject> unmarshalledProperties,
            QualifyingPropertyVerificationContext ctx)
            throws PropertyDataStructureException, InvalidPropertyException,
            QualifyingPropertyVerifierNotAvailableException
    {
        // old invocation method so use old implementation
        QualifyingPropertiesVerifier qpv = new QualifyingPropertiesVerifierImpl(
                propertyVerifiersMapper,
                dataObjectsStructureVerifier);

        return qpv.verifyProperties(unmarshalledProperties, ctx);
    }

    @Override
    public List<PropertyInfo> verifyProperties(
            HybridQualifPropsDataCollectorImpl propsDataCollector,
            QualifyingPropertyVerificationContext ctx,
            List<PropertyInfo> props)
    {
        // now we have full revocation information about Signature, go and verify
        // *Refs and SignatureCertificate properties

        List<PropertyInfo> newProps = new ArrayList<PropertyInfo>(props.size());
        for (PropertyInfo p : props)
        {
            if (p.getProperty() == null)
            {
                PropertyDataObject propData = p.getPropertyData();
                try {

                    QualifyingPropertyVerifier<PropertyDataObject> propVerifier =
                            this.propertyVerifiersMapper.getVerifier(propData);

                    Element elem = (Element) propsDataCollector.getPropertyNode(propData);

                    QualifyingProperty qp = propVerifier.verify(propData, elem, ctx);
                    if (qp == null)
                            throw new PropertyVerifierErrorException(propData
                                .getClass().getName());
                    newProps.add(new PropertyInfo(propData, qp));

                } catch (XAdES4jException e)
                {
                    System.out.println("Error when verifying "
                            + p.getPropertyData().getClass() + ", stack trace follows: ");
                    e.printStackTrace();
                    continue;
                }

            } else {
                newProps.add(p);
            }
        }

        return newProps;
    }

}
