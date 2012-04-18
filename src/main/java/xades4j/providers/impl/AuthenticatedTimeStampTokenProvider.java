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
package xades4j.providers.impl;

import com.google.inject.Inject;
import java.io.IOException;
import java.net.HttpURLConnection;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.utils.Base64;

/**
 * A {@link xades4j.providers.TimeStampTokenProvider} that issues time-stamp requests
 * over HTTP using basic authentication. When configuring a profile to use this type,
 * the authentication data should also be configured on the profile.
 * @see TSAHttpAuthenticationData
 * @author Luís
 */
public final class AuthenticatedTimeStampTokenProvider extends DefaultTimeStampTokenProvider
{
    private final String base64tsaUsrAndPwd;

    @Inject
    public AuthenticatedTimeStampTokenProvider(
            MessageDigestEngineProvider messageDigestProvider,
            TSAHttpAuthenticationData httpAuthenticationData)
    {
        super(messageDigestProvider, httpAuthenticationData.getTsaUrl());
        String usrAndPwd = httpAuthenticationData.getTsaUser() + ":" + httpAuthenticationData.getTsaPassword();
        this.base64tsaUsrAndPwd = Base64.encodeBytes(usrAndPwd.getBytes());
    }

    @Override
    HttpURLConnection getHttpConnection() throws IOException
    {
        HttpURLConnection connection = super.getHttpConnection();
        connection.setRequestProperty("Authorization", "Basic " + this.base64tsaUsrAndPwd);
        return connection;
    }
}
