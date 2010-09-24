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
package xades4j.properties.data;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Luís
 */
public abstract class BaseXAdESTimeStampData implements PropertyDataObject
{
    private final String canonicalizationAlgorithmUri;
    private final List<byte[]> timeStampTokens;

    /**
     * The token should NOT be encoded in base-64. This is done in the marshalling
     * stage.
     */
    protected BaseXAdESTimeStampData(
            String canonicalizationAlgorithmUri,
            byte[] tsToken)
    {
        this(canonicalizationAlgorithmUri);
        this.timeStampTokens.add(tsToken);
    }

    protected BaseXAdESTimeStampData(String canonicalizationAlgorithmUri)
    {
        this.canonicalizationAlgorithmUri = canonicalizationAlgorithmUri;
        this.timeStampTokens = new ArrayList<byte[]>(1);
    }

    /**
     * The token should NOT be encoded in base-64. This is done in the marshalling
     * stage.
     * @param tsToken the token
     */
    public void addTimeStampToken(byte[] tsToken)
    {
        this.timeStampTokens.add(tsToken);
    }

    public String getCanonicalizationAlgorithmUri()
    {
        return canonicalizationAlgorithmUri;
    }

    public List<byte[]> getTimeStampTokens()
    {
        return timeStampTokens;
    }
}
