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
import java.util.Collection;

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
            String canonicalizationAlgorithmUri,
            Collection<String> includes,
            byte[] tsToken)
    {
        super(canonicalizationAlgorithmUri, tsToken);
        this.includes = includes;
    }

    public IndividualDataObjsTimeStampData(String canonicalizationAlgorithmUri)
    {
        super(canonicalizationAlgorithmUri);
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
