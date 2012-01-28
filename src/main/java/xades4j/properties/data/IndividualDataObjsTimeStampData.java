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
import java.util.Collection;
import xades4j.algorithms.Algorithm;

/**
 *
 * @author Luís
 */
public final class IndividualDataObjsTimeStampData extends BaseXAdESTimeStampData
{
    private final Collection<String> includes;

    /**
     * The token should NOT be encoded in base-64. This is done in the marshalling
     * stage.
     */
    public IndividualDataObjsTimeStampData(
            Algorithm c14n,
            Collection<String> includes,
            byte[] tsToken)
    {
        super(c14n, tsToken);
        this.includes = includes;
    }

    public IndividualDataObjsTimeStampData(Algorithm c14n)
    {
        super(c14n);
        this.includes = new ArrayList<String>(3);
    }

    public void addInclude(String inc)
    {
        this.includes.add(inc);
    }

    public Collection<String> getIncludes()
    {
        return includes;
    }
}
