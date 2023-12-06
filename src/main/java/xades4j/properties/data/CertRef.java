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
package xades4j.properties.data;

import java.math.BigInteger;

/**
 *
 * @author Luís
 */
public class CertRef
{
    private final String digestAlgUri;
    private final byte[] digestValue;
    private final String issuerDN;
    private final BigInteger serialNumber;

    public CertRef(
            String issuerDN, BigInteger serialNumber,
            String digestAlgUri, byte[] digestValue)
    {
        this.digestAlgUri = digestAlgUri;
        this.digestValue = digestValue;
        this.issuerDN = issuerDN;
        this.serialNumber = serialNumber;
    }

    public String getDigestAlgUri() {
        return digestAlgUri;
    }

    /**
     * The digest value for the certificate, already decoded from base-64.
     */
    public byte[] getDigestValue() {
        return digestValue;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }
}
