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

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.naming.directory.InvalidAttributesException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Class wrapping Certificate and PrivateKey in a easy-to-use package, oriented to testing
 *
 * @author Hubert Kario
 *
 */
public class FullCert
{
    private X509Certificate certificate;
    private PrivateKey privateKey;

    public X509Certificate getCertificate()
    {
        return certificate;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    /**
     * @param algorithm key generation algorithm: RSA, DSA, ECDSA (currently only RSA is
     * supported)
     * @param keySize size of generated keys, for example 2048 for RSA and 521 for ECDSA
     * @param distinguishedName DN of the new certificate
     * @param notBefore time from which certificate is valid
     * @param notAfter time after which certificate is not valid
     * @param serialNumber this should be an <b>unique</b> serial number of the certificate
     * @param sigAlgorithm name of signature algorithm (SHA1withDSA, SHA256withRSA, etc.)
     * @param isCA should the new certificate be for a Certificate Authority
     * @param keyUsage valid key uses (bitwise OR on values from {@link KeyUsage}
     * @param extendedAttrCritical are extended key usage attributes critical
     * @param extendedAttr list of extended attributes, if null then no extended key
     * attributes will be added to certificate
     * @param signer certificate that has to sign new certificate, can be null,
     * then it will create a self-signed certificate
     * @return ready to use FullCert (certificate + private key)
     * @throws Exception on any error
     */
    private static FullCert signCert(
            String algorithm,
            int keySize,
            String distinguishedName,
            Date notBefore,
            Date notAfter,
            BigInteger serialNumber,
            String sigAlgorithm,
            boolean isCA,
            int keyUsage,
            boolean extendedAttrCritical,
            KeyPurposeId[] extendedAttr,
            FullCert signer) throws Exception
    {
        if (!algorithm.equalsIgnoreCase("RSA"))
            throw new InvalidAttributesException("Only RSA keys supported for the moment");

        // prepare parameters
        X500Principal subjectName = new X500Principal(distinguishedName);
        // generate key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, "BC");
        kpg.initialize(keySize);
        KeyPair keyPair = kpg.generateKeyPair();
        // extract public key as RSA public key
        java.security.interfaces.RSAPublicKey rsaPublicKey =
                (java.security.interfaces.RSAPublicKey) keyPair.getPublic();
        java.security.interfaces.RSAPublicKey caRSAPublicKey;
        if (signer != null)
        {
            caRSAPublicKey =
                (java.security.interfaces.RSAPublicKey) signer.certificate.getPublicKey();
        } else {
            caRSAPublicKey =
                (java.security.interfaces.RSAPublicKey) keyPair.getPublic();
        }

        // set basic information
        X509v3CertificateBuilder certBuilder;
        if (signer != null)
        {
            certBuilder = new JcaX509v3CertificateBuilder(
                    signer.certificate.getSubjectX500Principal(),
                    serialNumber,
                    notBefore,
                    notAfter,
                    subjectName,
                    keyPair.getPublic());
        } else {
            certBuilder = new JcaX509v3CertificateBuilder(
                    subjectName,
                    serialNumber,
                    notBefore,
                    notAfter,
                    subjectName,
                    keyPair.getPublic());
        }
        // used for creating extensions in certificate, depends on algorithm (RSA, DSA,
        // ECDSA)
        SubjectPublicKeyInfo subjectKeyInfo =
                new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                                DERNull.INSTANCE),
                        new RSAPublicKey(rsaPublicKey.getModulus(),
                                rsaPublicKey.getPublicExponent()));
        SubjectPublicKeyInfo issuerKeyInfo =
                new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                                DERNull.INSTANCE),
                        new RSAPublicKey(caRSAPublicKey.getModulus(),
                                caRSAPublicKey.getPublicExponent()));

        /*
         * Additional constraints are defaults from EJBCA
         */
        certBuilder.addExtension(X509Extension.subjectKeyIdentifier,
                false, /* extension should always be non critical */
                new SubjectKeyIdentifier(subjectKeyInfo));

        certBuilder.addExtension(X509Extension.basicConstraints,
                true, /* extension is critical */
                new BasicConstraints(isCA));

        certBuilder.addExtension(X509Extension.authorityKeyIdentifier,
                false, /* extension should always be non critical */
                new AuthorityKeyIdentifier(issuerKeyInfo));

        certBuilder.addExtension(X509Extension.keyUsage,
                true, /* is critical */
                new KeyUsage(keyUsage));

        if (extendedAttr != null)
        {
            certBuilder.addExtension(X509Extension.extendedKeyUsage,
                    extendedAttrCritical,
                    new ExtendedKeyUsage(new DERSequence(extendedAttr)));
        }

        // signature generator
        ContentSigner sigGen;
        if (signer != null)
        {
            sigGen = new JcaContentSignerBuilder(sigAlgorithm)
                            .setProvider("BC").build(signer.privateKey);
        } else {
            sigGen = new JcaContentSignerBuilder(sigAlgorithm)
                            .setProvider("BC").build(keyPair.getPrivate());
        }

        // export private key and signed certificate
        FullCert cert = new FullCert();
        cert.privateKey = keyPair.getPrivate();
        cert.certificate = new JcaX509CertificateConverter()
                            .setProvider("BC").getCertificate(certBuilder.build(sigGen));

        return cert;
    }

    /**
     * Generates Certificate with extensions useful for CA with serial number set at 1
     *
     * @param algorithm key generation algorithm: RSA, DSA, ECDSA, etc.
     * (currently only RSA is supported)
     * @param keySize size of generated keys, for example 2048 for RSA and 521 for ECDSA
     * @param distinguishedName DN of the CA
     * @param notBefore time from which certificate is valid
     * @param notAfter time after which certificate is not valid
     * @param sigAlgorithm name of signature algorithm (SHAwithDSA, SHA256withRSA, etc.)
     * @return Certificate together with private key
     * @throws Exception on any error
     */
    public static FullCert getCACert(
            String algorithm,
            int keySize,
            String distinguishedName,
            Date notBefore,
            Date notAfter,
            String sigAlgorithm) throws Exception
    {
        BigInteger serialNumber = new BigInteger("1");
        boolean isCA = true;
        int keyUsage = KeyUsage.digitalSignature | KeyUsage.keyCertSign
                | KeyUsage.cRLSign;
        boolean extendedAttrCritical = false;
        KeyPurposeId extendedAttr[] = null;
        FullCert signer = null;

        return signCert(algorithm,
                        keySize,
                        distinguishedName,
                        notBefore,
                        notAfter,
                        serialNumber ,
                        sigAlgorithm,
                        isCA,
                        keyUsage,
                        extendedAttrCritical,
                        extendedAttr,
                        signer);
    }

    /**
     * Uses current certificate as CA cert to create new user certificate with sane
     * default key usages and extended key usages. Does not set distribution points for
     * CRLs or OCSP
     * <p>
     * <b>Does not perform any sanity checks</b>
     * @param algorithm key generation algorithm: RSA, DSA, ECDSA
     * (currently only RSA is supported)
     * @param keySize size of generated keys, for example 2048 for RSA and 521 for ECDSA
     * @param distinguishedName DN of the user
     * @param notBefore time from which certificate is valid
     * @param notAfter time after which certificate is not valid
     * @param serialNumber this should be an <b>unique</b> serial number of the certificate
     * @param sigAlgorithm name of signature algorithm (SHAwithDSA, SHA256withRSA, etc.)
     * @return Certificate together with private key
     * @throws Exception on any error
     */
    public FullCert createUserCert(
            String algorithm,
            int keySize,
            String distinguishedName,
            Date notBefore,
            Date notAfter,
            BigInteger serialNumber,
            String sigAlgorithm) throws Exception
    {
        boolean isCA = false;
        int keyUsage = KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                | KeyUsage.dataEncipherment;
        boolean extendedAttrCritical = false;
        KeyPurposeId[] extendedAttr = new KeyPurposeId[3];
        extendedAttr[0] = KeyPurposeId.id_kp_clientAuth;
        extendedAttr[1] = KeyPurposeId.id_kp_codeSigning;
        extendedAttr[2] = KeyPurposeId.id_kp_emailProtection;

        return signCert(algorithm,
                        keySize,
                        distinguishedName,
                        notBefore,
                        notAfter,
                        serialNumber,
                        sigAlgorithm,
                        isCA,
                        keyUsage,
                        extendedAttrCritical,
                        extendedAttr,
                        this);
    }

    /**
     * Uses current certificate as CA cert to create new Time Stamping Authority (TSA)
     * certificate with default key usages and extended key usages typical for a TSA.
     * Does not set distribution points for CRLs or OCSP.
     * <p>
     * <b>Does not perform any sanity checks. Sets Extended Key Usage to critical.</b>
     * @param algorithm key generation algorithm: RSA, DSA, ECDSA
     * (currently only RSA is supported)
     * @param keySize size of generated keys, for example 2048 for RSA and 521 for ECDSA
     * @param distinguishedName DN of the user
     * @param notBefore time from which certificate is valid
     * @param notAfter time after which certificate is not valid
     * @param serialNumber this should be an <b>unique</b> serial number of the certificate
     * @param sigAlgorithm name of signature algorithm (SHAwithDSA, SHA256withRSA, etc.)
     * @return Certificate together with private key
     * @throws Exception on any error
     */
    public FullCert createTSACert(
            String algorithm,
            int keySize,
            String distinguishedName,
            Date notBefore,
            Date notAfter,
            BigInteger serialNumber,
            String sigAlgorithm) throws Exception
    {
        boolean isCA = false;
        int keyUsage = KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment;
        boolean extendedAttrCritical = true;
        KeyPurposeId[] extendedAttr = new KeyPurposeId[1];
        extendedAttr[0] = KeyPurposeId.id_kp_timeStamping;

        return signCert(algorithm,
                        keySize,
                        distinguishedName,
                        notBefore,
                        notAfter,
                        serialNumber,
                        sigAlgorithm,
                        isCA,
                        keyUsage,
                        extendedAttrCritical,
                        extendedAttr,
                        this);
    }

    /**
     * Uses current certificate as CA cert to create new sub CA certificate with sane
     * default key usages. Does not set distribution points for
     * CRLs or OCSP
     * <p>
     * <b>Does not perform any sanity checks</b>
     * @param algorithm key generation algorithm: RSA, DSA, ECDSA
     * (currently only RSA is supported)
     * @param keySize size of generated keys, for example 2048 for RSA and 521 for ECDSA
     * @param distinguishedName DN of the user
     * @param notBefore time from which certificate is valid
     * @param notAfter time after which certificate is not valid
     * @param serialNumber this should be an <b>unique</b> serial number of the certificate
     * @param sigAlgorithm name of signature algorithm (SHAwithDSA, SHA256withRSA, etc.)
     * @return Certificate together with private key
     * @throws Exception on any error
     */
    public FullCert createSubCACert(
            String algorithm,
            int keySize,
            String distinguishedName,
            Date notBefore,
            Date notAfter,
            BigInteger serialNumber,
            String sigAlgorithm) throws Exception
    {

        boolean isCA = true;
        int keyUsage = KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                | KeyUsage.dataEncipherment;
        boolean extendedAttrCritical = false;
        KeyPurposeId[] extendedAttr = null;

        return signCert(algorithm,
                        keySize,
                        distinguishedName,
                        notBefore,
                        notAfter,
                        serialNumber,
                        sigAlgorithm,
                        isCA,
                        keyUsage,
                        extendedAttrCritical,
                        extendedAttr ,
                        this);
    }

    /**
     * Class containing entries for conversion to CRL
     *
     * @author Hubert Kario
     *
     */
    public class CRLEntries
    {
        private List<BigInteger> serialNumber;
        private List<Date> revocationDate;
        private List<Integer> revocationReason;

        public CRLEntries()
        {
            serialNumber = new ArrayList<BigInteger>();
            revocationDate = new ArrayList<Date>();
            revocationReason = new ArrayList<Integer>();
        }

        public CRLEntries(CRLEntries old)
        {
            this.serialNumber = new ArrayList<BigInteger>(old.serialNumber);
            this.revocationDate = new ArrayList<Date>(old.revocationDate);
            this.revocationReason = new ArrayList<Integer>(old.revocationReason);
        }

        public void addEntry(BigInteger serialNumber, Date revocationDate,
                int revocationReason)
        {
            if (serialNumber == null || revocationDate == null)
                throw new InvalidParameterException("Parameters can't be null");
            if (revocationReason < 0)
                throw new InvalidParameterException("Revocation reason must be positive");

            this.serialNumber.add(serialNumber);
            this.revocationDate.add(revocationDate);
            this.revocationReason.add(revocationReason);
        }

        public int size()
        {
            return serialNumber.size();
        }

        public BigInteger getSerialNumber(int index)
        {
            return serialNumber.get(index);
        }

        public Date getRevocaDate(int index)
        {
            return revocationDate.get(index);
        }

        public int getRevocationReason(int index)
        {
            return revocationReason.get(index);
        }
    }

    /**
     * Create new certificate revocation list using this certificate as CA
     * @param sigAlgorithm CRL signature algorithm (for example SHA256withRSA)
     * @param thisUpdate date when this CRL has been created
     * @param nextUpdate when new CRL should have been created
     * @param serial Serial number of the CRL
     * @param entries list of revoked certificates
     * @return
     */
    public X509CRL createCRL(String sigAlgorithm,
            Date thisUpdate, Date nextUpdate, BigInteger serial, CRLEntries entries)
            throws Exception
    {
        java.security.interfaces.RSAPublicKey caRSAPublicKey =
                (java.security.interfaces.RSAPublicKey) certificate.getPublicKey();

        SubjectPublicKeyInfo issuerKeyInfo =
                new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                                DERNull.INSTANCE),
                        new RSAPublicKey(caRSAPublicKey.getModulus(),
                                caRSAPublicKey.getPublicExponent()));

        X500Name issuer = new X500Name(this.certificate.getSubjectDN().toString());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, thisUpdate);

        crlBuilder.setNextUpdate(nextUpdate);

        for (int i = 0; i < entries.size(); i++)
        {
            crlBuilder.addCRLEntry(
                    entries.getSerialNumber(i),
                    entries.getRevocaDate(i),
                    entries.getRevocationReason(i));
        }

        crlBuilder.addExtension(X509Extension.authorityKeyIdentifier,
                    false, /* not critical */
                    new AuthorityKeyIdentifier(issuerKeyInfo));

        crlBuilder.addExtension(X509Extension.cRLNumber,
                    false, /* not critical */
                    new CRLNumber(serial));

        // signature generator (use CA key)
        ContentSigner sigGen = new JcaContentSignerBuilder(sigAlgorithm)
                            .setProvider("BC").build(this.privateKey);

        X509CRLHolder crlHolder = crlBuilder.build(sigGen);
        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);
    }
}
