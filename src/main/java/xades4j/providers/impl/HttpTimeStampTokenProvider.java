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

import com.google.inject.Inject;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.utils.Base64;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Implementation of {@code AbstractTimeStampTokenProvider} that gets time-stamp tokens
 * from a HTTP TSA. Requests are issued with {@code certReq} set to
 * {@code true}. If username and password are set supplied, HTTP basic
 * authenticated will be used.
 *
 * @author luis
 */
public class HttpTimeStampTokenProvider extends AbstractTimeStampTokenProvider {
    private final TSAHttpData tsaHttpData;
    private final String base64TsaUsrAndPwd;

    @Inject
    public HttpTimeStampTokenProvider(MessageDigestEngineProvider messageDigestProvider, TSAHttpData tsaHttpData) {
        super(messageDigestProvider);
        this.tsaHttpData = tsaHttpData;
        if (tsaHttpData.getUsername() != null) {
            String usrAndPwd = tsaHttpData.getUsername() + ":" + tsaHttpData.getPassword();
            base64TsaUsrAndPwd = Base64.encodeBytes(usrAndPwd.getBytes());
        } else {
            base64TsaUsrAndPwd = null;
        }
    }

    protected byte[] getResponse(byte[] encodedRequest) throws TimeStampTokenGenerationException {
        HttpURLConnection connection = null;
        try {
            connection = createHttpConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-type", "application/timestamp-query");
            connection.setRequestProperty("Content-length", String.valueOf(encodedRequest.length));

            OutputStream out = connection.getOutputStream();
            out.write(encodedRequest);
            out.flush();

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new TimeStampTokenGenerationException(String.format("TSA returned HTTP %d %s", connection.getResponseCode(), connection.getResponseMessage()));
            }

            BufferedInputStream input = null;
            try {
                input = new BufferedInputStream(connection.getInputStream());
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int len;
                while ((len = input.read(buffer)) > -1) {
                    baos.write(buffer, 0, len);
                }
                baos.flush();

                return baos.toByteArray();
            } finally {
                if (input != null) input.close();
            }
        } catch (IOException ex) {
            throw new TimeStampTokenGenerationException("Error when connecting to the TSA", ex);
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private HttpURLConnection createHttpConnection() throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(this.temporaryGetTSAUrl()).openConnection();

        if (this.base64TsaUsrAndPwd != null) {
            connection.setRequestProperty("Authorization", "Basic " + this.base64TsaUsrAndPwd);
        }

        return connection;
    }

    /**
     * This package-private method is TEMPORARY until the deprecated
     * {@link DefaultTimeStampTokenProvider} is removed.
     */
    String temporaryGetTSAUrl() {
        return this.tsaHttpData.getUrl();
    }
}
