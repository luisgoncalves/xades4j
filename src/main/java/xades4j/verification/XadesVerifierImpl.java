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

import jakarta.inject.Inject;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.XAdES4jException;
import xades4j.XAdES4jXMLSigException;
import xades4j.production.XadesSignatureFormatExtender;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.UnsignedProperties;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.properties.data.CertRef;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.properties.data.SigningCertificateData;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.ValidationData;
import xades4j.providers.X500NameStyleProvider;
import xades4j.utils.CollectionUtils;
import xades4j.utils.ObjectUtils;
import xades4j.utils.PropertiesUtils;
import xades4j.utils.ResolverAnonymous;
import xades4j.verification.KeyInfoProcessor.KeyInfoRes;
import xades4j.verification.RawSignatureVerifier.RawSignatureVerifierContext;
import xades4j.verification.SignatureUtils.ReferencesRes;
import xades4j.xml.unmarshalling.QualifyingPropertiesUnmarshaller;
import xades4j.xml.unmarshalling.UnmarshalException;

import javax.annotation.Nullable;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static xades4j.verification.SignatureUtils.signatureReferencesElement;

/**
 * @author Luís
 */
class XadesVerifierImpl implements XadesVerifier
{

    static
    {
        org.apache.xml.security.Init.init();
        initFormExtension();
    }

    /**/
    private final CertificateValidationProvider certificateValidator;
    private final QualifyingPropertiesVerifier qualifyingPropertiesVerifier;
    private final QualifyingPropertiesUnmarshaller qualifPropsUnmarshaller;
    private final Set<RawSignatureVerifier> rawSigVerifiers;
    private final Set<CustomSignatureVerifier> customSigVerifiers;
    private final X500NameStyleProvider x500NameStyleProvider;
    private boolean secureValidation;
    private boolean requireSigningCertificateProperty;

    @Inject
    protected XadesVerifierImpl(
            CertificateValidationProvider certificateValidator,
            QualifyingPropertiesVerifier qualifyingPropertiesVerifier,
            QualifyingPropertiesUnmarshaller qualifPropsUnmarshaller,
            Set<RawSignatureVerifier> rawSigVerifiers,
            Set<CustomSignatureVerifier> customSigVerifiers,
            X500NameStyleProvider x500NameStyleProvider)
    {
        if (ObjectUtils.anyNull(
                certificateValidator, qualifyingPropertiesVerifier, qualifPropsUnmarshaller, rawSigVerifiers, customSigVerifiers))
        {
            throw new NullPointerException("One or more arguments are null");
        }

        this.certificateValidator = certificateValidator;
        this.qualifyingPropertiesVerifier = qualifyingPropertiesVerifier;
        this.qualifPropsUnmarshaller = qualifPropsUnmarshaller;
        this.rawSigVerifiers = rawSigVerifiers;
        this.customSigVerifiers = customSigVerifiers;
        this.x500NameStyleProvider = x500NameStyleProvider;
        this.secureValidation = false;
        this.requireSigningCertificateProperty = true;
    }

    void setAcceptUnknownProperties(boolean accept)
    {
        this.qualifPropsUnmarshaller.setAcceptUnknownProperties(accept);
    }

    void setSecureValidation(boolean secureValidation)
    {
        this.secureValidation = secureValidation;
    }

    void requireSigningCertificateProperty(boolean requireSigningCertificateProperty)
    {
        this.requireSigningCertificateProperty = requireSigningCertificateProperty;
    }

    @Override
    public XAdESVerificationResult verify(Element signatureElem, SignatureSpecificVerificationOptions verificationOptions) throws XAdES4jException
    {
        if (null == signatureElem)
        {
            throw new NullPointerException("Signature node not specified");
        }

        if (null == verificationOptions)
        {
            verificationOptions = SignatureSpecificVerificationOptions.EMPTY;
        }

        /* Unmarshal the signature */

        XMLSignature signature;
        try
        {
            signature = new XMLSignature(signatureElem, verificationOptions.getBaseUri(), this.secureValidation);
        }
        catch (XMLSecurityException ex)
        {
            throw new UnmarshalException("Bad XML signature", ex);
        }

        String signatureId = signature.getId();
        if (null == signatureId)
        {
            throw new UnmarshalException("XML signature doesn't have an Id");
        }

        ReferencesRes referencesRes = SignatureUtils.processReferences(signature);

        /* Apply early verifiers */

        RawSignatureVerifierContext rawCtx = new RawSignatureVerifierContext(signature);
        for (RawSignatureVerifier rawSignatureVerifier : this.rawSigVerifiers)
        {
            rawSignatureVerifier.verify(rawCtx);
        }

        /* Get and check the QualifyingProperties element */

        Element qualifyingPropsElem = SignatureUtils.getQualifyingPropertiesElement(signature);
        SignatureUtils.checkSignedPropertiesIncorporation(qualifyingPropsElem, referencesRes.signedPropsReference);

        // Check the QualifyingProperties 'Target' attribute.
        String targetValue = getTargetValue(qualifyingPropsElem);
        if (null == targetValue
                || !targetValue.startsWith("#")
                || !targetValue.substring(1).equals(signatureId))
        {
            throw new QualifyingPropertiesIncorporationException("QualifyingProperties target doesn't match the signature's Id");
        }

        /* Unmarshal the qualifying properties */

        QualifPropsDataCollectorImpl propsDataCollector = new QualifPropsDataCollectorImpl();
        qualifPropsUnmarshaller.unmarshalProperties(qualifyingPropsElem, propsDataCollector);
        Collection<PropertyDataObject> qualifPropsData = propsDataCollector.getPropertiesData();

        /* Certification path */

        Date validationDate = getValidationDate(qualifPropsData, signature, verificationOptions);
        CertRef signingCertRefAttempt = tryGetSigningCertificateRef(qualifPropsData);
        KeyInfoRes keyInfoRes = KeyInfoProcessor.process(signature.getKeyInfo(), signingCertRefAttempt, this.x500NameStyleProvider);
        ValidationData certValidationRes = this.certificateValidator.validate(
                keyInfoRes.signingCertSelector,
                validationDate,
                keyInfoRes.certs);
        if (null == certValidationRes || certValidationRes.getCerts().isEmpty())
        {
            throw new NullPointerException("Certificate validator returned null or empty data");
        }
        X509Certificate validationCert = certValidationRes.getCerts().get(0);

        checkKeyUsage(verificationOptions, validationCert);

        /* Signature verification */

        // Core XML-DSIG verification.
        doCoreVerification(signature, verificationOptions, validationCert);

        // Create the property verification context.
        QualifyingPropertyVerificationContext qPropsCtx = new QualifyingPropertyVerificationContext(
                signature,
                new QualifyingPropertyVerificationContext.CertificationChainData(
                        certValidationRes.getCerts(),
                        certValidationRes.getCrls(),
                        keyInfoRes.issuerSerial,
                        this.x500NameStyleProvider),
                /**/
                new QualifyingPropertyVerificationContext.SignedObjectsData(
                        referencesRes.dataObjsReferences,
                        signature));

        // Verify the properties. Data structure verification is included.
        Collection<PropertyInfo> props = this.qualifyingPropertiesVerifier.verifyProperties(qualifPropsData, qPropsCtx);
        // Determine the XAdES form by checking which (needed) properties are present.
        XAdESForm signatureForm = XAdESFormChecker.checkForm(props, requiresSigningCertificateProperty(signature, keyInfoRes));

        XAdESVerificationResult res = new XAdESVerificationResult(
                signatureForm,
                signature,
                certValidationRes,
                props,
                referencesRes.dataObjsReferences);

        // Apply the custom signature verifiers.
        for (CustomSignatureVerifier customVer : this.customSigVerifiers)
        {
            customVer.verify(res, qPropsCtx);
        }

        return res;
    }

    private static String getTargetValue(Element qualifyingPropsElem) throws QualifyingPropertiesIncorporationException
    {
        Node targetAttr = qualifyingPropsElem.getAttributeNodeNS(null, QualifyingProperty.TARGET_ATTR);
        if (null == targetAttr)
        {
            targetAttr = qualifyingPropsElem.getAttributeNodeNS(QualifyingProperty.XADES_XMLNS, QualifyingProperty.TARGET_ATTR);
            if (null == targetAttr)
            {
                throw new QualifyingPropertiesIncorporationException("QualifyingProperties Target attribute not present");
            }
        }
        return targetAttr.getNodeValue();
    }

    /*************************************************************************************/

    @Nullable
    private CertRef tryGetSigningCertificateRef(Collection<PropertyDataObject> qualifPropsData)
    {
        // If the SigningCertificate property contains a single reference, it likely represents the signer's certificate.
        // In that case, it can be used as a fallback to identify the signing certificate when processing KeyInfo.
        // This is a temporary solution.
        // - Properties should probably be verified in two stages (before and after cert path creation).
        List<SigningCertificateData> certData = CollectionUtils.filterByType(qualifPropsData, SigningCertificateData.class);
        if (certData.size() == 1)
        {
            Collection<CertRef> certRefs = certData.get(0).getCertRefs();
            if (certRefs.size() == 1)
            {
                return certRefs.iterator().next();
            }
        }

        return null;
    }

    private static void checkKeyUsage(SignatureSpecificVerificationOptions verificationOptions, X509Certificate validationCert) throws SigningCertificateKeyUsageException
    {
        if (verificationOptions.checkKeyUsage())
        {
            // Check key usage.
            // - KeyUsage[0] = digitalSignature
            // - KeyUsage[1] = nonRepudiation
            boolean[] keyUsage = validationCert.getKeyUsage();
            if (keyUsage != null && !keyUsage[0] && !keyUsage[1])
            {
                throw new SigningCertificateKeyUsageException();
            }
        }
    }

    private Date getValidationDate(
            Collection<PropertyDataObject> qualifPropsData,
            XMLSignature signature,
            SignatureSpecificVerificationOptions verificationOptions) throws XAdES4jException
    {
        List<? extends PropertyDataObject> sigTsData = CollectionUtils.filterByType(qualifPropsData, SignatureTimeStampData.class);

        // If no signature time-stamp is present, use the current date.
        if (sigTsData.isEmpty())
        {
            return verificationOptions.getDefaultVerificationDate();
        }

        // TODO support multiple SignatureTimeStamps (section 7.3 last paragraph of Standard v.1.4.2)
        // This is a temporary solution.
        // - Properties should probably be verified in two stages (before and after cert path creation).
        // - Had to remove the custom structure verifier that checked if the SigningCertificate data was present.
        QualifyingPropertyVerificationContext ctx = new QualifyingPropertyVerificationContext(
                signature,
                new QualifyingPropertyVerificationContext.CertificationChainData(
                        new ArrayList<>(0),
                        new ArrayList<>(0),
                        null,
                        this.x500NameStyleProvider),
                /**/
                new QualifyingPropertyVerificationContext.SignedObjectsData(
                        new ArrayList<>(0),
                        signature));
        Collection<PropertyInfo> props = this.qualifyingPropertiesVerifier.verifyProperties((Collection<PropertyDataObject>) sigTsData, ctx);
        QualifyingProperty sigTs = props.iterator().next().getProperty();

        return ((SignatureTimeStampProperty) sigTs).getTime();
    }

    /**
     * Determines if the SigningCertificate qualifying property must be in the signature. This depends on whether the
     * signing certificate is protected in KeyInfo and what the profile allows.
     * Note that the property is not required but is present, it's still validatated as any other property.
     */
    private boolean requiresSigningCertificateProperty(XMLSignature signature, KeyInfoRes keyInfoRes) throws XAdES4jException
    {
        if (this.requireSigningCertificateProperty)
        {
            // Profile requires protecting the signing certificate using the SigningCertificate property.
            return true;
        }

        if (!keyInfoRes.signingCertSelectorFromKeyInfo)
        {
            // KeyInfo does not contain elements that identify the signing certificate, which means the
            // SigningCertificate property must be used. This was already checked when processing KeyInfo, anyway.
            return true;
        }

        try
        {
            // KeyInfo contains elements that identify the signing certificate. If these elements are not protected by
            // the signature, then the SigningCertificate property is required.
            // Note that this only supports References to the KeyInfo element itself, containing only C14N transforms.
            return !signatureReferencesElement(signature, signature.getKeyInfo());
        }
        catch (XMLSecurityException e)
        {
            throw new XAdES4jXMLSigException("Error looking for KeyInfo reference", e);
        }
    }

    private static void doCoreVerification(
            XMLSignature signature,
            SignatureSpecificVerificationOptions verificationOptions,
            X509Certificate validationCert) throws XAdES4jXMLSigException, InvalidSignatureException
    {
        List<ResourceResolverSpi> resolvers = verificationOptions.getResolvers();
        if (!CollectionUtils.nullOrEmpty(resolvers))
        {
            for (ResourceResolverSpi resolver : resolvers)
            {
                signature.addResourceResolver(resolver);
            }
        }

        signature.setFollowNestedManifests(verificationOptions.isFollowManifests());

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
            }
            else
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

    /*************************************************************************************/
    private interface FormExtensionPropsCollector
    {

        void addProps(Collection<UnsignedSignatureProperty> usp,
                      XAdESVerificationResult res);
    }

    private static FormExtensionPropsCollector[][] formsExtensionTransitions;

    private static void initFormExtension()
    {
        XAdESForm[] forms = XAdESForm.values();
        formsExtensionTransitions = new FormExtensionPropsCollector[forms.length][forms.length];

        // BES/EPES -> T
        FormExtensionPropsCollector tPropsCol = (usp, res) -> PropertiesUtils.addXadesTProperties(usp);
        formsExtensionTransitions[XAdESForm.BES.ordinal()][XAdESForm.T.ordinal()] = tPropsCol;
        formsExtensionTransitions[XAdESForm.EPES.ordinal()][XAdESForm.T.ordinal()] = tPropsCol;

        // BES/EPES -> C
        FormExtensionPropsCollector cAndTPropsCol = (usp, res) -> {
            PropertiesUtils.addXadesCProperties(usp, res.getValidationData());
            PropertiesUtils.addXadesTProperties(usp);
        };
        formsExtensionTransitions[XAdESForm.BES.ordinal()][XAdESForm.C.ordinal()] = cAndTPropsCol;
        formsExtensionTransitions[XAdESForm.EPES.ordinal()][XAdESForm.C.ordinal()] = cAndTPropsCol;

        // T -> C
        FormExtensionPropsCollector cPropsCol = (usp, res) -> PropertiesUtils.addXadesCProperties(usp, res.getValidationData());
        formsExtensionTransitions[XAdESForm.T.ordinal()][XAdESForm.C.ordinal()] = cPropsCol;

        // C -> X
        FormExtensionPropsCollector xPropsCol = (usp, res) -> PropertiesUtils.addXadesXProperties(usp);
        formsExtensionTransitions[XAdESForm.C.ordinal()][XAdESForm.X.ordinal()] = xPropsCol;

        // C -> X-L
        FormExtensionPropsCollector xlAndXPropsCol = (usp, res) -> {
            PropertiesUtils.addXadesXLProperties(usp, res.getValidationData());
            PropertiesUtils.addXadesXProperties(usp);
        };
        formsExtensionTransitions[XAdESForm.C.ordinal()][XAdESForm.X_L.ordinal()] = xlAndXPropsCol;
    }

    @Override
    public XAdESVerificationResult verify(
            Element signatureElem,
            SignatureSpecificVerificationOptions verificationOptions,
            XadesSignatureFormatExtender formatExtender,
            XAdESForm finalForm) throws XAdES4jException
    {
        if (null == finalForm || null == formatExtender)
        {
            throw new NullPointerException("'finalForm' and 'formatExtender' cannot be null");
        }

        // The transition matrix won't allow this, but this way I avoid the
        // unnecessary processing.
        if (finalForm.before(XAdESForm.T) || finalForm.after(XAdESForm.X_L))
        {
            throw new IllegalArgumentException("Signature format can only be extended to XAdES-T, C, X or X-L");
        }

        XAdESVerificationResult res = this.verify(signatureElem, verificationOptions);
        XAdESForm actualForm = res.getSignatureForm();

        if (actualForm.before(finalForm))
        {
            // Valid form transitions:
            // * BES/EPES -> T
            // * BES/EPES -> C
            // * T -> C
            // * C -> X
            // * C -> X-L
            // * X -> X-L (not supported with the library defaults: X cannot be verified)
            // * X-L -> A (not supported with the library defaults: X-L cannot be verified)

            FormExtensionPropsCollector finalFormPropsCollector = getFinalFormPropsColector(finalForm, actualForm);

            Collection<UnsignedSignatureProperty> usp = new ArrayList<>(3);
            finalFormPropsCollector.addProps(usp, res);

            formatExtender.enrichSignature(res.getXmlSignature(), new UnsignedProperties(usp));
        }
        return res;
    }

    private static FormExtensionPropsCollector getFinalFormPropsColector(XAdESForm finalForm, XAdESForm actualForm) throws InvalidFormExtensionException
    {
        FormExtensionPropsCollector finalFormPropsCollector = formsExtensionTransitions[actualForm.ordinal()][finalForm.ordinal()];

        if (null == finalFormPropsCollector)
        {
            throw new InvalidFormExtensionException(actualForm, finalForm);
        }
        return finalFormPropsCollector;
    }
}
