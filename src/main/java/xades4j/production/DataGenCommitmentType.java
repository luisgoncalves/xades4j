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
package xades4j.production;

import xades4j.properties.DataObjectDesc;
import java.util.Collection;
import java.util.Map;
import org.apache.xml.security.signature.Reference;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.properties.data.PropertyDataObject;

/**
 *
 * @author Luís
 */
class DataGenCommitmentType implements PropertyDataObjectGenerator<CommitmentTypeProperty>
{
    @Override
    public PropertyDataObject generatePropertyData(
            CommitmentTypeProperty prop,
            PropertiesDataGenerationContext ctx)
    {
        CommitmentTypeData commTypeData = new CommitmentTypeData(
                prop.getUri(),
                prop.getDescription());

        /* One ObjectReference element refers to one ds:Reference element of the
         * ds:SignedInfo corresponding with one data object qualified by this
         * property. If some but not all the signed data objects share the same
         * commitment, one ObjectReference element MUST appear for each one of
         * them. However, if all the signed data objects share the same commitment,
         * the AllSignedDataObjects empty element MUST be present.
         */

        Collection<DataObjectDesc> targets = prop.getTargetDataObjects();
        Map<DataObjectDesc, Reference> referencesMappings = ctx.getReferencesMappings();

        for (DataObjectDesc obj : targets)
        {
            // The ObjectReference refers the Reference element. This assumes
            // that the QualifyingProperties are in the signature's document.
            commTypeData.addObjReferences('#' + referencesMappings.get(obj).getId());
        }

        commTypeData.setQualifiers(prop.getQualifiers());
        
        return commTypeData;
    }
}
