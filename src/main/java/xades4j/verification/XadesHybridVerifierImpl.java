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

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverAnonymous;
import org.w3c.dom.Element;

import com.google.inject.Inject;

import xades4j.XAdES4jException;
import xades4j.XAdES4jXMLSigException;
import xades4j.production.XadesSignatureFormatExtender;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.UnsignedProperties;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.ValidationData;
import xades4j.utils.CollectionUtils;
import xades4j.utils.PropertiesUtils;
import xades4j.verification.RawSignatureVerifier.RawSignatureVerifierContext;
import xades4j.verification.SignatureUtils.KeyInfoRes;
import xades4j.verification.SignatureUtils.ReferencesRes;
import xades4j.xml.unmarshalling.QualifyingPropertiesUnmarshaller;
import xades4j.xml.unmarshalling.UnmarshalException;

public class XadesHybridVerifierImpl implements XadesVerifier
{
    static
    {
        org.apache.xml.security.Init.init();
        initFormExtension();
    }
    private final CertificateValidationProvider certificateValidator;
    private final QualifyingPropertiesVerifier qualifyingPropertiesVerifier;
    private final Set<RawSignatureVerifier> rawSigVerifiers;
    private final Set<CustomSignatureVerifier> customSigVerifiers;
    private QualifyingPropertiesUnmarshaller qualifPropsUnmarshaller;
    private boolean secureValidation;

    @Inject
    protected XadesHybridVerifierImpl(
            CertificateValidationProvider certificateValidator,
            QualifyingPropertiesVerifier qualifyingPropertiesVerifier,
            QualifyingPropertiesUnmarshaller qualifyingPropsUnmarshaller,
            Set<RawSignatureVerifier> rawSigVerifiers,
            Set<CustomSignatureVerifier> customSigVerifiers)
    {
        this.certificateValidator = certificateValidator;
        this.qualifyingPropertiesVerifier = qualifyingPropertiesVerifier;
        this.qualifPropsUnmarshaller = qualifyingPropsUnmarshaller;
        this.rawSigVerifiers = rawSigVerifiers;
        this.customSigVerifiers = customSigVerifiers;
        this.secureValidation = false;
    }

    @Override
    public XAdESVerificationResult verify(Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions)
            throws XAdES4jException
    {
        if (signatureElem == null)        {
            throw new NullPointerException("Signature node not specified");
        }

        if (verificationOptions == null)
        {
            verificationOptions = SignatureSpecificVerificationOptions.empty();
        }

        /*
         * Unmarshal XMLdsig (basic XML signature)
         */
        XMLSignature signature;
        try
        {
            signature = new XMLSignature(signatureElem, verificationOptions.getBaseUri(), this.secureValidation);
        } catch (XMLSecurityException ex)
        {
            throw new UnmarshalException("Bad XML signature", ex);
        }

        // XMLDsig doesn't require Id, but XAdES does
        String signatureId = signature.getId();
        if (null == signatureId)
        {
            throw new UnmarshalException("XML signature doesn't have an Id");
        }

        // extract references to SignedProperties element and signed data objects
        ReferencesRes referencesRes = SignatureUtils.processReferences(signature);

        /*
         * Apply early verifiers
         */
        RawSignatureVerifierContext rawCtx = new RawSignatureVerifierContext(signature);
        for (RawSignatureVerifier rawSignatureVerifier : this.rawSigVerifiers)
        {
            rawSignatureVerifier.verify(rawCtx);
        }

        /*
         * Get the QualifyingProperties element and check if it's properly embedded in
         * signature (Signature references it and vice versa)
         */
        Element qualifyingPropsElem =
                SignatureUtils.getQualifyingPropertiesElement(signature);
        SignatureUtils.checkSignedPropertiesIncorporation(
                qualifyingPropsElem,
                referencesRes.signedPropsReference);
        SignatureUtils.checkQualifyingPropertiesTarget(signatureId, qualifyingPropsElem);

        /* Unmarshal the qualifying (XAdES, both signed and unsigned) properties */
        HybridQualifPropsDataCollectorImpl propsDataCollector =
                new HybridQualifPropsDataCollectorImpl();
        qualifPropsUnmarshaller.unmarshalProperties(qualifyingPropsElem, propsDataCollector);

        /*
         * extract data that uniquely identifies the key and/or certificate used for
         * Signature signing from basic XML signature (XMLdsig)
         */
        KeyInfoRes keyInfoRes = SignatureUtils.processKeyInfo(signature.getKeyInfo());

        /*
         * Create the object which the property verifiers will use to get and save
         * the status (context) of verification
         */
        QualifyingPropertyVerificationContext qPropsCtx = new QualifyingPropertyVerificationContext(
                signature,
                keyInfoRes,
                /**/
                new QualifyingPropertyVerificationContext.SignedObjectsData(
                referencesRes.dataObjsReferences,
                signature),
                verificationOptions.getDefaultVerificationDate());

        /*
         * go over all qualified properties in reverse order, verify the properties,
         * ignore invalid and return only successfully verified.
         * Data structure verification is included.
         *
         * This is the first verification that ignores certificate and CRL references
         * (as we know which certificates are needed and which CRLs are used only after
         * verification of Signature)
         */
        List<PropertyInfo> props =
                this.qualifyingPropertiesVerifier.verifyProperties(propsDataCollector, qPropsCtx);

        /* create certification path */
        Date validationDate = getValidationDate(props, verificationOptions);
        this.certificateValidator.addCertificates(qPropsCtx.getSignatureCertificates(),
                validationDate);
        this.certificateValidator.addCRLs(qPropsCtx.getSignatureCRLs(), validationDate);

        ValidationData certValidationRes = this.certificateValidator.validate(
                keyInfoRes.certSelector,
                validationDate,
                keyInfoRes.keyInfoCerts);

        if (null == certValidationRes || certValidationRes.getCerts().isEmpty())
        {
            throw new NullPointerException("Certificate validator returned null or empty data");
        }
        X509Certificate validationCert = certValidationRes.getCerts().get(0);

        /* Signature verification */

        // Core XML-DSIG verification.
        doCoreVerification(signature, verificationOptions, validationCert);


        if (null == certValidationRes || certValidationRes.getCerts().isEmpty())
        {
            throw new NullPointerException("Certificate validator returned null or empty data");
        }

        // perform verification of references to certificates and CRLs (revocation data)
        qPropsCtx.setCertificationChainData(
                new QualifyingPropertyVerificationContext.CertificationChainData(
                        certValidationRes.getCerts(),
                        certValidationRes.getCrls(),
                        keyInfoRes.issuerSerial));
        props = this.qualifyingPropertiesVerifier.verifyProperties(propsDataCollector, qPropsCtx, props);

        XAdESVerificationResult res = new XAdESVerificationResult(
                XAdESFormChecker.checkForm(props),
                signature,
                certValidationRes,
                qPropsCtx.getAttributeValidationData(),
                props,
                referencesRes.dataObjsReferences);

        // Apply the custom signature verifiers.
        for (CustomSignatureVerifier customVer : this.customSigVerifiers)
        {
            customVer.verify(res, qPropsCtx);
        }

        return res;
    }

    @Override
    public XAdESVerificationResult verify(Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions,
            XadesSignatureFormatExtender formatExtender, XAdESForm finalForm)
            throws XAdES4jException
    {
        if (null == finalForm || null == formatExtender)        {
            throw new NullPointerException("'finalForm' and 'formatExtender' cannot be null");
        }

        // The transitions matrix won't allow this, but this way I avoid the
        // unnecessary processing.
        if (finalForm.before(XAdESForm.T) || finalForm.after(XAdESForm.A_VD))
        {
            throw new IllegalArgumentException("Signature format can only be extended to XAdES-T or above");
        }

        XAdESVerificationResult res = this.verify(signatureElem, verificationOptions);
        XAdESForm actualForm = res.getSignatureForm();

        if (!finalForm.before(actualForm))
        {
            // Valid form transitions:
            // * BES/EPES -> T
            // * BES/EPES -> C
            // * T -> T
            // * T -> C
            // * C -> X
            // * C -> X-L
            // * X -> X
            // * X -> X-L
            // * X-L -> A
            // * A -> A
            // * A -> A-VD (A-VD is not a real form, it's used to tell library to create
            //              TimesStampValidationData element)

            FormExtensionPropsCollector finalFormPropsColector = formsExtensionTransitions[actualForm.ordinal()][finalForm.ordinal()];

            if (null == finalFormPropsColector)
            {
                throw new InvalidFormExtensionException(actualForm, finalForm);
            }

            Collection<UnsignedSignatureProperty> usp = new ArrayList<UnsignedSignatureProperty>(3);
            finalFormPropsColector.addProps(usp, res);

            formatExtender.enrichSignature(res.getXmlSignature(), new UnsignedProperties(usp));
        }
        return res;
    }

    private static interface FormExtensionPropsCollector    {

        void addProps(Collection<UnsignedSignatureProperty> usp,
                XAdESVerificationResult res);
    }
    private static FormExtensionPropsCollector[][] formsExtensionTransitions;

    private static void initFormExtension()
    {
        XAdESForm[] forms = XAdESForm.values();
        formsExtensionTransitions = new FormExtensionPropsCollector[forms.length][forms.length];

        // BES/EPES -> T
        FormExtensionPropsCollector tPropsCol = new FormExtensionPropsCollector()
        {

            @Override
            public void addProps(
                    Collection<UnsignedSignatureProperty> usp,
                    XAdESVerificationResult res)
            {
                PropertiesUtils.addXadesTProperties(usp);
            }
        };
        formsExtensionTransitions[XAdESForm.BES.ordinal()][XAdESForm.T.ordinal()] = tPropsCol;
        formsExtensionTransitions[XAdESForm.EPES.ordinal()][XAdESForm.T.ordinal()] = tPropsCol;
        // T -> T
        formsExtensionTransitions[XAdESForm.T.ordinal()][XAdESForm.T.ordinal()] = tPropsCol;

        // BES/EPES -> C
        FormExtensionPropsCollector cAndTPropsCol = new FormExtensionPropsCollector()
        {

            @Override
            public void addProps(
                    Collection<UnsignedSignatureProperty> usp,
                    XAdESVerificationResult res)
            {
                PropertiesUtils.addXadesTProperties(usp);
                PropertiesUtils.addXadesCProperties(usp, res.getValidationData());
            }
        };
        formsExtensionTransitions[XAdESForm.BES.ordinal()][XAdESForm.C.ordinal()] = cAndTPropsCol;
        formsExtensionTransitions[XAdESForm.EPES.ordinal()][XAdESForm.C.ordinal()] = cAndTPropsCol;

        // T -> C
        FormExtensionPropsCollector cPropsCol = new FormExtensionPropsCollector()
        {

            @Override
            public void addProps(
                    Collection<UnsignedSignatureProperty> usp,
                    XAdESVerificationResult res)
            {
                PropertiesUtils.addXadesCProperties(usp, res.getValidationData());
            }
        };
        formsExtensionTransitions[XAdESForm.T.ordinal()][XAdESForm.C.ordinal()] = cPropsCol;

        // C -> X
        FormExtensionPropsCollector xPropsCol = new FormExtensionPropsCollector()
        {

            @Override
            public void addProps(
                    Collection<UnsignedSignatureProperty> usp,
                    XAdESVerificationResult res)
            {
                PropertiesUtils.addXadesXProperties(usp);
            }
        };
        formsExtensionTransitions[XAdESForm.C.ordinal()][XAdESForm.X.ordinal()] = xPropsCol;
        // X -> X
        formsExtensionTransitions[XAdESForm.X.ordinal()][XAdESForm.X.ordinal()] = xPropsCol;

        // C -> X-L
        FormExtensionPropsCollector xlAndXPropsCol = new FormExtensionPropsCollector()
        {

            @Override
            public void addProps(
                    Collection<UnsignedSignatureProperty> usp,
                    XAdESVerificationResult res)
            {
                PropertiesUtils.addXadesXProperties(usp);

                Collection<ValidationData> tTimeStampValidationData =
                        PropertiesUtils.extractTTimeStampValidationData(res);

                PropertiesUtils.addXadesXLProperties(usp, res.getValidationData(),
                        tTimeStampValidationData);
            }
        };
        formsExtensionTransitions[XAdESForm.C.ordinal()][XAdESForm.X_L.ordinal()] = xlAndXPropsCol;

        // X -> X-L
        FormExtensionPropsCollector xlPropsCol = new FormExtensionPropsCollector()
        {
            @Override
            public void addProps(Collection<UnsignedSignatureProperty> usp,
                    XAdESVerificationResult res)
            {
                Collection<ValidationData> tTimeStampValidationData =
                        PropertiesUtils.extractTTimeStampValidationData(res);

                PropertiesUtils.addXadesXLProperties(
                        usp,
                        res.getValidationData(),
                        tTimeStampValidationData);
            }

        };
        formsExtensionTransitions[XAdESForm.X.ordinal()][XAdESForm.X_L.ordinal()] = xlPropsCol;

        // X-L -> A
        FormExtensionPropsCollector aPropsCol = new FormExtensionPropsCollector()
        {
            @Override
            public void addProps(Collection<UnsignedSignatureProperty> usp,
                    XAdESVerificationResult res)
            {
                PropertiesUtils.addXadesAProperties(usp);
            }
        };
        formsExtensionTransitions[XAdESForm.X_L.ordinal()][XAdESForm.A.ordinal()] = aPropsCol;
        // A -> A
        formsExtensionTransitions[XAdESForm.A.ordinal()][XAdESForm.A.ordinal()] = aPropsCol;

        // A -> A-VD
        FormExtensionPropsCollector avdPropsCol = new FormExtensionPropsCollector()
        {
            @Override
            public void addProps(Collection<UnsignedSignatureProperty> usp,
                    XAdESVerificationResult res)
            {
                PropertiesUtils.addXadesAVDProperties(usp, res);
            }
        };
        formsExtensionTransitions[XAdESForm.A.ordinal()][XAdESForm.A_VD.ordinal()] = avdPropsCol;
    }

    public void setAcceptUnknownProperties(boolean acceptUnknownProperties)
    {
        this.qualifPropsUnmarshaller.setAcceptUnknownProperties(acceptUnknownProperties);
    }

    void setSecureValidation(boolean secureValidation) {
        this.secureValidation = secureValidation;
    }

    private static void doCoreVerification(
            XMLSignature signature,
            SignatureSpecificVerificationOptions verificationOptions,
            X509Certificate validationCert) throws XAdES4jXMLSigException, InvalidSignatureException
    {
        List<ResourceResolver> resolvers = verificationOptions.getResolvers();
        if(!CollectionUtils.nullOrEmpty(resolvers))
        {
            for (ResourceResolver resolver : resolvers)
            {
                signature.addResourceResolver(resolver);
            }
        }

        InputStream nullURIReferenceData = verificationOptions.getDataForAnonymousReference();
        if (nullURIReferenceData != null)
        {
            signature.addResourceResolver(new ResolverAnonymous(nullURIReferenceData));
        }

        try
        {
            if (signature.checkSignatureValue(validationCert))
            {
                return;
            }
        }
        catch (XMLSignatureException ex)
        {
            throw new XAdES4jXMLSigException("Error verifying the signature", ex);
        }

        try
        {
            /* Failure due to the signature value or references validation? */

            if (signature.getSignedInfo().verifyReferences())
            // References are OK; this is a problem on the signature value
            // itself.
            {
                throw new SignatureValueException(signature);
            } else
            {
                // References are NOT OK; get the first invalid Reference.
                SignedInfo si = signature.getSignedInfo();
                for (int i = 0; i < si.getLength(); i++)
                {
                    Reference r = si.item(i);
                    if (!r.verify())
                    {
                        throw new ReferenceValueException(signature, r);
                    }
                }
            }
        }
        catch (XMLSecurityException ex)
        {
            throw new XAdES4jXMLSigException("Error verifying the references", ex);
        }
    }

    private Date getValidationDate(
            List<PropertyInfo> props, SignatureSpecificVerificationOptions verificationOptions)
            throws XAdES4jException    {
        Date earliestDate = null;
        for (PropertyInfo p : props)
        {
            QualifyingProperty qp = p.getProperty();
            if (qp instanceof SignatureTimeStampProperty)
            {
                Date timeStampDate = ((SignatureTimeStampProperty)qp).getTime();
                if (earliestDate == null)
                    earliestDate = timeStampDate;
                else if (earliestDate.getTime() > timeStampDate.getTime())
                    earliestDate = timeStampDate;
            } else if (qp instanceof SigAndRefsTimeStampProperty)
            {
                Date timeStampDate = ((SigAndRefsTimeStampProperty)qp).getTime();
                if (earliestDate == null)
                    earliestDate = timeStampDate;
                else if (earliestDate.getTime() > timeStampDate.getTime())
                    earliestDate = timeStampDate;
            } else if (qp instanceof ArchiveTimeStampProperty)
            {
                Date timeStampDate = ((ArchiveTimeStampProperty)qp).getTime();
                if (earliestDate == null)
                    earliestDate = timeStampDate;
                else if (earliestDate.getTime() > timeStampDate.getTime())
                    earliestDate = timeStampDate;
            }
        }
        if (earliestDate == null) {
            earliestDate = verificationOptions.getDefaultVerificationDate();
        }

        return earliestDate;
    }

}
