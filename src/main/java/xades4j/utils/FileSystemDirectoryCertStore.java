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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Creates a {@code CertStore} from the contents of a file-system directory. The
 * directories are recusively searched for X509 certificates or CRLs files that
 * have one of the specified extensions.
 * @author Luís
 */
public class FileSystemDirectoryCertStore
{
    private final CertStore content;

    /**
     * Creates a new instance over a directory. The {@code cer} and {@code crt}
     * extesions are considered for certificates and {@code crl} for CRLs.
     * @param dirPath the path for the base directory
     * @throws CertificateException if there's an error reading the certificates
     * @throws CRLException if there's an error reading the CRLs
     */
    public FileSystemDirectoryCertStore(String dirPath) throws CertificateException, CRLException
    {
        this(dirPath, new String[]
                {
                    "cer", "crt"
                }, new String[]
                {
                    "crl"
                });
    }

    /**
     * Creates a new instance over a directory using the specified extensions
     * @param dirPath the path for the base directory
     * @param certsFilesExts extensions for included certificate files
     * @param crlsFilesExts  extensions for included CRL files
     * @throws CertificateException if there's an error reading the certificates
     * @throws CRLException if there's an error reading the CRLs
     */
    public FileSystemDirectoryCertStore(
            String dirPath,
            final String[] certsFilesExts,
            final String[] crlsFilesExts) throws CertificateException, CRLException
    {
        File dir = new File(dirPath);
        if (!dir.exists() || !dir.isDirectory())
            throw new IllegalArgumentException("Specified path doesn't exist or doesn't refer a directory");

        Collection contentList = new ArrayList();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        transverseDirToFindContent(dir, contentList, certsFilesExts, crlsFilesExts, cf);

        try
        {
            this.content = CertStore.getInstance("Collection", new CollectionCertStoreParameters(contentList));
            return;
        } catch (InvalidAlgorithmParameterException ex)
        {
        } catch (NoSuchAlgorithmException ex)
        {
        }
        // ToDo: this is a bit ugly!
        throw new CertificateException("Error getting Collection CertStore");
    }

    private void transverseDirToFindContent(
            File dir,
            Collection contentList,
            String[] certsFilesExts,
            String[] crlsFilesExts,
            CertificateFactory cf) throws CertificateException, CRLException
    {
        File[] dirContents = dir.listFiles();
        for (int i = 0; i < dirContents.length; i++)
        {
            File f = dirContents[i];

            if (f.isDirectory())
                transverseDirToFindContent(f, contentList, certsFilesExts, crlsFilesExts, cf);
            else if (f.isFile())
                try
                {
                    if (hasExt(f, certsFilesExts))
                        contentList.add((X509Certificate)cf.generateCertificate(new FileInputStream(f)));
                    else if (hasExt(f, crlsFilesExts))
                        contentList.add((X509CRL)cf.generateCRL(new FileInputStream(f)));
                } catch (FileNotFoundException ex)
                {
                    // The file existed right up there! If somehow it doesn't exist
                    // now, nevermind.
                }
        }
    }

    private boolean hasExt(File f, String[] filesExts)
    {
        for (int j = 0; j <
                filesExts.length; j++)
        {
            if (f.getName().endsWith('.' + filesExts[j]))
                return true;
        }
        return false;
    }

    /**
     * Gets the {@code CertStore} resulting from this instance.
     * @return the {@code CertStore} containing all the certificates and CRLs that were found
     */
    public CertStore getStore()
    {
        return content;
    }
}
