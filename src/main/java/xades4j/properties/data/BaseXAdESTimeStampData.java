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

import java.util.ArrayList;
import java.util.List;
import xades4j.algorithms.Algorithm;

/**
 *
 * @author Luís
 */
public abstract class BaseXAdESTimeStampData implements PropertyDataObject
{
    private final Algorithm c14n;
    private final List<byte[]> timeStampTokens;

    /**
     * The token should NOT be encoded in base-64. This is done in the marshalling
     * stage.
     */
    protected BaseXAdESTimeStampData(Algorithm c14n, byte[] tsToken)
    {
        this(c14n);
        this.timeStampTokens.add(tsToken);
    }

    protected BaseXAdESTimeStampData(Algorithm c14n)
    {
        this.c14n = c14n;
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

    public Algorithm getCanonicalizationAlgorithm()
    {
        return this.c14n;
    }

    @Deprecated
    public String getCanonicalizationAlgorithmUri()
    {
        return this.c14n.getUri();
    }

    public List<byte[]> getTimeStampTokens()
    {
        return this.timeStampTokens;
    }
}
