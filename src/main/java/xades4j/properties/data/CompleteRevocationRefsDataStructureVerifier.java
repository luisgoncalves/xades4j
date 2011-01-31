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
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.utils.ObjectUtils;

/**
 *
 * @author Luís
 */
class CompleteRevocationRefsDataStructureVerifier implements PropertyDataObjectStructureVerifier
{
    @Override
    public void verifyStructure(PropertyDataObject propData) throws PropertyDataStructureException
    {
        Collection<CRLRef> crlRefs = ((CompleteRevocationRefsData)propData).getCrlRefs();

        if (null == crlRefs || crlRefs.isEmpty())
            throw new PropertyDataStructureException("empty CRL reference list", CompleteRevocationRefsProperty.PROP_NAME);

        for (CRLRef r : crlRefs)
        {
            if (null == r)
                throw new PropertyDataStructureException("null CRL reference", CompleteRevocationRefsProperty.PROP_NAME);
            if (ObjectUtils.anyNull(
                    r.issuerDN,
                    r.digestAlgUri,
                    r.digestValue,
                    r.issueTime))
                throw new PropertyDataStructureException("empty data on one or more CRL references", CompleteRevocationRefsProperty.PROP_NAME);
        }
    }
}
