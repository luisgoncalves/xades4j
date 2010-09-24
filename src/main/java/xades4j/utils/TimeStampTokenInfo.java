/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

/**
 * Represents the TSTInfo strcture within a time-stamp token (RFC 3161).
 * Based on the sun.security.timestamp.TimestampToken class.
 * Copyright 2006 Sun Microsystems, Inc. All rights reserved.
 * author: Vincent Ryan
 * <p>
 * Added getters for fields other than genTime.
 * @author Luís
 */
public class TimeStampTokenInfo
{
    private int version;
    private ObjectIdentifier policy;
    private BigInteger serialNumber;
    private AlgorithmId hashAlgorithm;
    private byte[] hashedMessage;
    private Date genTime;

    /**
     * Constructs an object to store a timestamp token.
     *
     * @param timestampTokenInfo a buffer containing the ASN.1 BER encoding of the
     *               TSTInfo element defined in RFC 3161.
     */
    public TimeStampTokenInfo(byte[] timestampTokenInfo) throws IOException
    {
        if (timestampTokenInfo == null)
            throw new IOException("No timestamp token info");
        parse(timestampTokenInfo);
    }

    /**
     * Extract the date and time from the timestamp token.
     *
     * @return The date and time when the timestamp was generated.
     */
    public Date getDate()
    {
        return genTime;
    }

    public AlgorithmId getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    public byte[] getHashedMessage()
    {
        return hashedMessage;
    }

    public ObjectIdentifier getPolicy()
    {
        return policy;
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

    public int getVersion()
    {
        return version;
    }

    /*
     * Parses the timestamp token info.
     *
     * @param timestampTokenInfo A buffer containing an ASN.1 BER encoded
     *                           TSTInfo.
     * @throws IOException The exception is thrown if a problem is encountered
     *         while parsing.
     */
    private void parse(byte[] timestampTokenInfo) throws IOException
    {

        DerValue tstInfo = new DerValue(timestampTokenInfo);
        if (tstInfo.tag != DerValue.tag_Sequence)
            throw new IOException("Bad encoding for timestamp token info");
        // Parse version
        version = tstInfo.data.getInteger();

        // Parse policy
        policy = tstInfo.data.getOID();

        // Parse messageImprint
        DerValue messageImprint = tstInfo.data.getDerValue();
        hashAlgorithm = AlgorithmId.parse(messageImprint.data.getDerValue());
        hashedMessage = messageImprint.data.getOctetString();

        // Parse serialNumber
        serialNumber = tstInfo.data.getBigInteger();

        // Parse genTime
        genTime = tstInfo.data.getGeneralizedTime();

        // Parse optional elements, if present
        if (tstInfo.data.available() > 0)
        {
            // Parse accuracy
            // Parse ordering
            // Parse nonce
            // Parse tsa
            // Parse extensions
        }
    }
}
