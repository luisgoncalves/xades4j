/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2017 Luis Goncalves.
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
package xades4j.providers.impl;

/**
 * Configuration to access a TSA over HTTP. This class is typically used with
 * {@link HttpTimeStampTokenProvider} by registering an instance with the
 * appropriate URL and (optionally) username and password on the
 * signing/verification profile.
 *
 * @author Luís
 */
public final class TSAHttpData
{
    private final String url;
    private final String username;
    private final String password;

    public TSAHttpData(String url, String username, String password)
    {
        if (url == null)
        {
            throw new NullPointerException("tsaUrl must not be null");
        }

        if (username == null ^ password == null)
        {
            throw new NullPointerException("Both username and password must be supplied");
        }

        this.url = url;
        this.username = username;
        this.password = password;
    }

    public TSAHttpData(String url)
    {
        this(url, null, null);
    }

    public String getUrl()
    {
        return url;
    }

    public String getUsername()
    {
        return username;
    }

    public String getPassword()
    {
        return password;
    }
}
