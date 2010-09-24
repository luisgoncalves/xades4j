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
package xades4j.production;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import xades4j.properties.QualifyingProperty;

/**
 *
 * @author Luís
 */
class Init
{
    private Init()
    {
    }

    static void initXMLSec()
    {
        org.apache.xml.security.Init.init();
        try
        {
            ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
            ElementProxy.setDefaultPrefix(QualifyingProperty.XADES_XMLNS, "xades");
            ElementProxy.setDefaultPrefix(QualifyingProperty.XADESV141_XMLNS, "xades141");
        } catch (XMLSecurityException ex)
        {
        }
    }
}
