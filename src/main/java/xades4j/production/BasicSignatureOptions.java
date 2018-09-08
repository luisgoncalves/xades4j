/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2018 Luis Goncalves.
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

/**
 * Configuration of basic signature options such as whether {@code ds:KeyInfo}
 * elements should be included.
 *
 * @author luis
 */
public final class BasicSignatureOptions
{
    private boolean includeSigningCertificate;
    private boolean includeSubjectName;
    private boolean includeIssuerSerial;
    private boolean includePublicKey;
    private boolean signKeyInfo;

    /**
     * Configures whether the signing certificate should be included in {@code ds:KeyInfo}.
     * @param includeSigningCertificate {@code true} if the certificate should be included; false otherwise
     * @return the current instance
     */
    public BasicSignatureOptions includeSigningCertificate(boolean includeSigningCertificate)
    {
        this.includeSigningCertificate = includeSigningCertificate;
        return this;
    }
    
    boolean includeSigningCertificate()
    {
        return this.includeSigningCertificate;
    }

    /**
     * Configures whether the subject name should be included in {@code ds:KeyInfo}.
     * @param includeSubjectName {@code true} if the subject name should be included; false otherwise
     * @return the current instance
     */
    public BasicSignatureOptions includeSubjectName(boolean includeSubjectName)
    {
        this.includeSubjectName = includeSubjectName;
        return this;
    }

    boolean includeSubjectName()
    {
        return this.includeSubjectName;
    }

    /**
     * Configures whether the issuer/serial should be included in {@code ds:KeyInfo}.
     * @param includeIssuerSerial {@code true} if the issuer/serial should be included; false otherwise
     * @return the current instance
     */
    public BasicSignatureOptions includeIssuerSerial(boolean includeIssuerSerial)
    {
        this.includeIssuerSerial = includeIssuerSerial;
        return this;
    }
    
    boolean includeIssuerSerial()
    {
        return this.includeIssuerSerial;
    }

    /**
     * Configures whether a {@code ds:KeyValue} element containing the public key's
     * value should be included in {@code ds:KeyInfo}.
     * @param includePublicKey {@code true} if the public key should be included; false otherwise
     * @return the current instance
     */
    public BasicSignatureOptions includePublicKey(boolean includePublicKey)
    {
        this.includePublicKey = includePublicKey;
        return this;
    }
    
    boolean includePublicKey()
    {
        return this.includePublicKey;
    }
    /**
     * Configures whether the signature should cover the {@code ds:KeyInfo} element.
     *
     * @param signKeyInfo {@code true} if the {@code ds:KeyInfo} should be signed; false otherwise
     * @return the current instance
     */
    public BasicSignatureOptions signKeyInfo(boolean signKeyInfo)
    {
        this.signKeyInfo = signKeyInfo;
        return this;
    }

    boolean signKeyInfo()
    {
        return this.signKeyInfo;
    }
}
