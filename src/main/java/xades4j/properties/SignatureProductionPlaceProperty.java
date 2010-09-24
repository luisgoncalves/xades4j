/*
 *  XAdES4j - A Java library for generation and verification of XAdES signatures.
 *  Copyright (C) 2010 Luis Goncalves.
 * 
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation; either version 2 of the License, or any later version.
 * 
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 *  Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.properties;

/**
 * The {@code SignatureProductionPlace} property indicates the purported place
 * where the signer was at the time of signature creation.
 * <p>
 * This is a signed property that qualifies the signer. There shall be at most one
 * occurence of this property in the signature.
 * @see xades4j.providers.SignaturePropertiesProvider
 * @author Luís
 */
public final class SignatureProductionPlaceProperty extends SignedSignatureProperty
{
    public static final String PROP_NAME = "SignatureProductionPlace";
    /**/
    private final String city, stateOrProvince, postalCode, country;

    public SignatureProductionPlaceProperty(String city, String country)
    {
        this(city, null, null, country);
    }

    public SignatureProductionPlaceProperty(
            String city, String stateOrProvince,
            String postalCode, String country)
    {
        this.city = city;
        this.stateOrProvince = stateOrProvince;
        this.postalCode = postalCode;
        this.country = country;
    }

    public String getCity()
    {
        return city;
    }

    public String getCountry()
    {
        return country;
    }

    public String getPostalCode()
    {
        return postalCode;
    }

    public String getStateOrProvince()
    {
        return stateOrProvince;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
