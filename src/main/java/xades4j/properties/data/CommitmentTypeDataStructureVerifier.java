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
