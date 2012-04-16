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
package xades4j.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Utility methods for streams.
 * @author Luís
 */
public class StreamUtils
{
    private StreamUtils()
    {
    }

    /**
     * Reads the content of an input stream and writes it into an output stream.
     * The copy is made in chunks of 1 KB.
     * @param is the input
     * @param os the output
     * @throws IOException thrown by the {@code read} and {@code write} methods of the streams
     */
    public static void readWrite(InputStream is, OutputStream os) throws IOException
    {
        byte[] buf = new byte[1024];
        int nRead;
        while ((nRead = is.read(buf)) != -1)
        {
            os.write(buf, 0, nRead);
        }
    }
}
