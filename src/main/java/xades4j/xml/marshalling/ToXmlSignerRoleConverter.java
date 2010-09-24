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
package xades4j.xml.marshalling;

import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignerRoleData;
import xades4j.xml.bind.xades.XmlAnyType;
import xades4j.xml.bind.xades.XmlClaimedRolesListType;
import xades4j.xml.bind.xades.XmlSignedPropertiesType;
import xades4j.xml.bind.xades.XmlSignerRoleType;

/**
 *
 * @author Luís
 */
class ToXmlSignerRoleConverter implements SignedPropertyDataToXmlConverter
{
    @Override
    public void convertIntoObjectTree(
            PropertyDataObject propData,
            XmlSignedPropertiesType xmlProps)
    {
        SignerRoleData signerRoleData = (SignerRoleData)propData;

        XmlSignerRoleType xmlSignerRole = new XmlSignerRoleType();

        XmlClaimedRolesListType xmlClaimedRoles = new XmlClaimedRolesListType();
        xmlSignerRole.setClaimedRoles(xmlClaimedRoles);

        for (String r : signerRoleData.getClaimedRoles())
        {
            XmlAnyType xmlRole = new XmlAnyType();
            xmlRole.getContent().add(r);
            xmlClaimedRoles.getClaimedRole().add(xmlRole);
        }

        xmlProps.getSignedSignatureProperties().setSignerRole(xmlSignerRole);
    }
}
