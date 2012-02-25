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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
 * have one of the specified extensions. If the JCE provider is not supplied, the
 * CertificateFactory is obtained without specifying a provider.
 * @author Luís
 */
public class FileSystemDirectoryCertStore
{
    private static final String[] DEFAULT_CERT_FILE_EXT = { "cer", "crt" };
    private static final String[] DEFAULT_CRL_FILE_EXT = { "crl" };

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
        this(dirPath, DEFAULT_CERT_FILE_EXT, DEFAULT_CRL_FILE_EXT);
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
        this(dirPath, certsFilesExts, crlsFilesExts, CertificateFactory.getInstance("X.509"));
    }

    /**
     * Creates a new instance over a directory using the specified JCE provider.
     * The {@code cer} and {@code crt} extesions are considered for certificates
     * and {@code crl} for CRLs.
     * @param dirPath the path for the base directory
     * @param certFactoryProvider the JCE provider for the CertificateFactory used
     *                        to generate certificates and CRLs
     * @throws CertificateException if there's an error reading the certificates
     * @throws CRLException if there's an error reading the CRLs
     * @throws NoSuchProviderException if {@code certFactoryProvider} doesn't exist
     */
    public FileSystemDirectoryCertStore(
            String dirPath,
            String certFactoryProvider) throws CertificateException, CRLException, NoSuchProviderException
    {
        this(dirPath, DEFAULT_CERT_FILE_EXT, DEFAULT_CRL_FILE_EXT, certFactoryProvider);
    }

    /**
     * Creates a new instance over a directory using the specified extensions and
     * JCE provider.
     * @param dirPath the path for the base directory
     * @param certsFilesExts extensions for included certificate files
     * @param crlsFilesExts  extensions for included CRL files
     * @param certFactoryProvider the JCE provider for the CertificateFactory used
     *                        to generate certificates and CRLs
     * @throws CertificateException if there's an error reading the certificates
     * @throws CRLException if there's an error reading the CRLs
     * @throws NoSuchProviderException if {@code certFactoryProvider} doesn't exist
     */
    public FileSystemDirectoryCertStore(
            String dirPath,
            String[] certsFilesExts,
            String[] crlsFilesExts,
            String certFactoryProvider) throws CertificateException, CRLException, NoSuchProviderException
    {
        this(dirPath, certsFilesExts, crlsFilesExts, CertificateFactory.getInstance("X.509", certFactoryProvider));
    }

    /**
     * Creates a new instance over a directory using the specified extensions
     * @param dirPath the path for the base directory
     * @param certsFilesExts extensions for included certificate files
     * @param crlsFilesExts  extensions for included CRL files
     * @throws CertificateException if there's an error reading the certificates
     * @throws CRLException if there's an error reading the CRLs
     */
    protected FileSystemDirectoryCertStore(
            String dirPath,
            final String[] certsFilesExts,
            final String[] crlsFilesExts,
            CertificateFactory cf) throws CertificateException, CRLException
    {
        File dir = new File(dirPath);
        if (!dir.exists() || !dir.isDirectory())
            throw new IllegalArgumentException("Specified path doesn't exist or doesn't refer a directory");

        Collection contentList = new ArrayList();
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
        return this.content;
    }
}
