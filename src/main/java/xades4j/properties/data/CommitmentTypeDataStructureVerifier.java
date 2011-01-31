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

import java.util.Collection;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.utils.StringUtils;

/**
 *
 * @author Luís
 */
class CommitmentTypeDataStructureVerifier implements PropertyDataObjectStructureVerifier
{
    @Override
    public void verifyStructure(PropertyDataObject propData) throws PropertyDataStructureException
    {
        CommitmentTypeData commTypeData = (CommitmentTypeData)propData;

        if (StringUtils.isNullOrEmptyString(commTypeData.getUri()))
            throw new PropertyDataStructureException("null URI", CommitmentTypeProperty.PROP_NAME);

        Collection<String> objReferences = commTypeData.getObjReferences();
        if (objReferences != null && objReferences.isEmpty())
            throw new PropertyDataStructureException("Object references is empty", CommitmentTypeProperty.PROP_NAME);
    }
}
