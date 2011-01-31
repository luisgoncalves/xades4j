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

/**
 *
 * @author Luís
 */
public final class SignatureProdPlaceData implements PropertyDataObject
{
    private final String city;
    private final String state;
    private final String postalCode;
    private final String country;

    public SignatureProdPlaceData(String city, String state, String postalCode,
            String country)
    {
        this.city = city;
        this.state = state;
        this.postalCode = postalCode;
        this.country = country;
    }

    /**
     * Get the value of country
     *
     * @return the value of country
     */
    public String getCountry()
    {
        return country;
    }

    /**
     * Get the value of state
     *
     * @return the value of state
     */
    public String getState()
    {
        return state;
    }

    /**
     * Get the value of postalCode
     *
     * @return the value of postalCode
     */
    public String getPostalCode()
    {
        return postalCode;
    }

    /**
     * Get the value of city
     *
     * @return the value of city
     */
    public String getCity()
    {
        return city;
    }
}
