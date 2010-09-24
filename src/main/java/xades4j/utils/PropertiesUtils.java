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
package xades4j.utils;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.ValidationData;

/**
 *
 * @author Luís
 */
public class PropertiesUtils
{
    private PropertiesUtils()
    {
    }

    public static void addXadesEpesProperties(
            Collection<SignedSignatureProperty> ssp,
            SignaturePolicyInfoProvider policyInfoProvider)
    {
        SignaturePolicyBase policyProp = policyInfoProvider.getSignaturePolicy();
        if (null == policyProp)
            throw new NullPointerException("Null policy");
        ssp.add(policyProp);
    }

    public static void addXadesTProperties(
            Collection<UnsignedSignatureProperty> usp)
    {
        usp.add(new SignatureTimeStampProperty());
    }

    public static void addXadesCProperties(
            Collection<UnsignedSignatureProperty> usp,
            ValidationData vData)
    {
        // Remove the leaf certificate.
        List<X509Certificate> caCerts = vData.getCerts();
        caCerts = new ArrayList<X509Certificate>(caCerts.subList(1, caCerts.size()));

        usp.add(new CompleteCertificateRefsProperty(caCerts));
        usp.add(new CompleteRevocationRefsProperty(vData.getCrls()));
    }

    public static void addXadesXProperties(
            Collection<UnsignedSignatureProperty> usp)
    {
        usp.add(new SigAndRefsTimeStampProperty());
    }

    public static void addXadesXLProperties(
            Collection<UnsignedSignatureProperty> usp,
            ValidationData vData)
    {
        usp.add(new CertificateValuesProperty(vData.getCerts()));
        usp.add(new RevocationValuesProperty(vData.getCrls()));
    }

    public static void addXadesAProperties(
            Collection<UnsignedSignatureProperty> usp)
    {
        usp.add(new ArchiveTimeStampProperty());
    }
}
