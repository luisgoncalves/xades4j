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

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import xades4j.properties.AllDataObjsTimeStampProperty;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.AttrAuthoritiesCertValuesProperty;
import xades4j.properties.AttributeRevocationValuesProperty;
import xades4j.properties.BaseXAdESTimeStampProperty;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.TimeStampValidationDataProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.ValidationData;
import xades4j.verification.XAdESVerificationResult;

/**
 *
 * @author Luís
 */
public class PropertiesUtils
{
    private static final long ONE_WEEK = 7 * 24 * 60 * 60 * 1000;

    private PropertiesUtils()
    {
    }

    public static void addXadesEpesProperties(
            Collection<SignedSignatureProperty> ssp,
            SignaturePolicyInfoProvider policyInfoProvider)
    {
        SignaturePolicyBase policyProp = policyInfoProvider.getSignaturePolicy();
        if (null == policyProp)
            throw new NullPointerException("Null policy");
        ssp.add(policyProp);
    }

    public static void addXadesTProperties(
            Collection<UnsignedSignatureProperty> usp)
    {
        usp.add(new SignatureTimeStampProperty());
    }

    public static void addXadesCProperties(
            Collection<UnsignedSignatureProperty> usp,
            ValidationData vData)
    {
        // Remove the leaf certificate.
        List<X509Certificate> caCerts = vData.getCerts();
        caCerts = new ArrayList<X509Certificate>(caCerts.subList(1, caCerts.size()));

        usp.add(new CompleteCertificateRefsProperty(caCerts));
        usp.add(new CompleteRevocationRefsProperty(vData.getCrls()));
    }

    public static void addXadesXProperties(
            Collection<UnsignedSignatureProperty> usp)
    {
        usp.add(new SigAndRefsTimeStampProperty());
    }

    public static void addXadesXLProperties(
            Collection<UnsignedSignatureProperty> usp,
            ValidationData vData,
            Collection<ValidationData> tstValData)
    {
        usp.add(new CertificateValuesProperty(vData.getCerts()));
        usp.add(new RevocationValuesProperty(vData.getCrls()));

        Collection<X509Certificate> allTSACerts = new HashSet<X509Certificate>();
        Collection<X509CRL> allTSACRLs = new HashSet<X509CRL>();
        for (ValidationData valData : tstValData)
        {
            allTSACerts.addAll(valData.getCerts());
            allTSACRLs.addAll(valData.getCrls());
        }
        usp.add(new AttrAuthoritiesCertValuesProperty(allTSACerts));
        usp.add(new AttributeRevocationValuesProperty(allTSACRLs));
    }

    public static void addXadesAProperties(
            Collection<UnsignedSignatureProperty> usp)
    {
        usp.add(new ArchiveTimeStampProperty());
    }

    public static void addXadesAVDProperties(
            Collection<UnsignedSignatureProperty> usp,
            XAdESVerificationResult res)
    {
        /*
         * The problem: the only CRLs that can contribute to validation of already
         * time stamped time stamps (SigAndRefsTimeStamp when the last time stamp is
         * AchiveTimeStamp) are ones that have been published after the time of last
         * time stamp. See "grace period" in XAdES standard.
         *
         * The problem is multiplied by the fact, that we can have multiple
         * ArchiveTimeStamps from different TSAs created in short succession.
         *
         * To detect which CRLs are published after the grace period, we assume that the
         * sum of grace period time and the difference between time of creation of
         * ArchiveTimeStamps is no greater than 1 week.
         * We then add only CRLs that have been published a week after
         */
        Collection<X509Certificate> allCertificates = new HashSet<X509Certificate>();
        Collection<X509CRL> crlsAfterGracePeriod = new HashSet<X509CRL>();

        Collection<BaseXAdESTimeStampProperty> timeStamps = new ArrayList<BaseXAdESTimeStampProperty>(
                res.getPropertiesFilter().getOfType(AllDataObjsTimeStampProperty.class));
        timeStamps.addAll(
                res.getPropertiesFilter().getOfType(IndividualDataObjsTimeStampProperty.class));
        timeStamps.addAll(
                res.getPropertiesFilter().getOfType(SignatureTimeStampProperty.class));
        timeStamps.addAll(
                res.getPropertiesFilter().getOfType(SigAndRefsTimeStampProperty.class));
        timeStamps.addAll(
                res.getPropertiesFilter().getOfType(ArchiveTimeStampProperty.class));

        /* get validation data that may be useful to add to TimeStampValidationData */
        for (BaseXAdESTimeStampProperty ts : timeStamps)
        {
            allCertificates.addAll(ts.getValidationData().getCerts());

            for (X509CRL crl : ts.getValidationData().getCrls())
            {
                // see big comment above
                if (ts.getTime().getTime() + ONE_WEEK < crl.getThisUpdate().getTime())
                    crlsAfterGracePeriod.add(crl);
            }
        }

        Collection<X509Certificate> savedCertificates = new ArrayList<X509Certificate>();
        Collection<X509CRL> savedCRLs = new ArrayList<X509CRL>();

        // collect all CRLs already present in signature
        Collection<RevocationValuesProperty> revValProps =
                res.getPropertiesFilter().getOfType(RevocationValuesProperty.class);
        Collection<AttributeRevocationValuesProperty> attrRevValProps =
                res.getPropertiesFilter().getOfType(AttributeRevocationValuesProperty.class);
        Collection<TimeStampValidationDataProperty> tsValDatProps =
                res.getPropertiesFilter().getOfType(TimeStampValidationDataProperty.class);
        for (RevocationValuesProperty revValProp : revValProps)
        {
            savedCRLs.addAll(revValProp.getCrls());
        }
        for (AttributeRevocationValuesProperty attrRevValProp : attrRevValProps)
        {
            savedCRLs.addAll(attrRevValProp.getCrls());
        }
        for (TimeStampValidationDataProperty tsValDataProp : tsValDatProps)
        {
            savedCRLs.addAll(tsValDataProp.getCrls());
            savedCertificates.addAll(tsValDataProp.getCertificates());
        }

        // collect all certificates specified in properties (there can be certificates
        // in time stamp tokens or basic XML signature KeyInfo, but duplication of them
        // is not an error in itself)
        Collection<CertificateValuesProperty> certValProps =
                res.getPropertiesFilter().getOfType(CertificateValuesProperty.class);
        Collection<AttrAuthoritiesCertValuesProperty> attrAuthCerValProps =
                res.getPropertiesFilter().getOfType(AttrAuthoritiesCertValuesProperty.class);
        for (CertificateValuesProperty cvProp : certValProps)
        {
            savedCertificates.addAll(cvProp.getCertificates());
        }
        for (AttrAuthoritiesCertValuesProperty aacvProp : attrAuthCerValProps)
        {
            savedCertificates.addAll(aacvProp.getCertificates());
        }

        // remove already saved validation information
        Collection <X509Certificate> certsToSave =
                new ArrayList<X509Certificate>(allCertificates);
        Collection <X509CRL> crlsToSave = new ArrayList<X509CRL>(crlsAfterGracePeriod);
        certsToSave.removeAll(savedCertificates);
        crlsToSave.removeAll(savedCRLs);

        usp.add(new TimeStampValidationDataProperty(certsToSave, crlsToSave));
    }

    /**
     * Walk over all properties with time stamps that can appear before X-L form
     * creation and extract Validation Data from each and every one of them.
     */
    public static Collection<ValidationData> extractTTimeStampValidationData(
            XAdESVerificationResult res)
    {
        Collection<ValidationData> tTimeStampValidationData =
                new ArrayList<ValidationData>();

        /*
         * Collect validation data of properties previous to the last time stamp
         * (SigAndRefsTimeStamp or RefsOnlyTimeStamp).
         *
         * This is done because the SigAndRefsTimeStamp must be valid using
         * current revocation information, the previous time stamps may be invalid
         * using currently available revocation information. In effect we save
         * only the information that will not change in future.
         *
         * To reduce amount of information needed to add in the future, we add all
         * certificates needed to verify the SigAndRefsTimeStamp too
         */
        Collection<AllDataObjsTimeStampProperty> allDataObjTSProps =
                res.getPropertiesFilter().getOfType(AllDataObjsTimeStampProperty.class);
        Collection<IndividualDataObjsTimeStampProperty> indivDataObjTSProps =
                res.getPropertiesFilter().getOfType(IndividualDataObjsTimeStampProperty.class);
        Collection<SignatureTimeStampProperty> sigTSProps =
                res.getPropertiesFilter().getOfType(SignatureTimeStampProperty.class);
        Collection<SigAndRefsTimeStampProperty> sigAndRefsProps =
                res.getPropertiesFilter().getOfType(SigAndRefsTimeStampProperty.class);

        for (AllDataObjsTimeStampProperty tsProp : allDataObjTSProps)
        {
            tTimeStampValidationData.add(tsProp.getValidationData());
        }
        for (IndividualDataObjsTimeStampProperty tsProp : indivDataObjTSProps)
        {
            tTimeStampValidationData.add(tsProp.getValidationData());
        }
        for (SignatureTimeStampProperty tsProp : sigTSProps)
        {
            tTimeStampValidationData.add(tsProp.getValidationData());
        }
        for (SigAndRefsTimeStampProperty tsProp : sigAndRefsProps)
        {
            ValidationData savedValData;
            savedValData = tsProp.getValidationData();
            ValidationData newValData = new ValidationData(savedValData.getCerts());
            tTimeStampValidationData.add(newValData);
        }
        return tTimeStampValidationData;
    }
}
