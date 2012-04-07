/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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

package xades4j.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 *
 * @author Luís
 */
public class CrlExtensionsUtils
{
    private CrlExtensionsUtils()
    {
    }

    public static BigInteger getCrlNumber(X509CRL crl) throws IOException
    {
        byte[] crlNumEnc = crl.getExtensionValue(X509Extension.cRLNumber.getId());
        BigInteger crlNum = null;
        // XAdES 7.4.2: "The 'number' element is an optional hint ..."
        if (crlNumEnc != null)
        {
            ASN1Object derCrlNum = X509ExtensionUtil.fromExtensionValue(crlNumEnc);
            crlNum = CRLNumber.getInstance(derCrlNum).getCRLNumber();
        }
        return crlNum;
    }
}
