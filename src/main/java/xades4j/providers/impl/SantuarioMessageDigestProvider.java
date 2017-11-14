package xades4j.providers.impl;

import org.apache.xml.security.algorithms.JCEMapper;
import xades4j.UnsupportedAlgorithmException;
import xades4j.providers.MessageDigestEngineProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * Adapter for <a href="http://santuario.apache.org/">Apache Santuario</a> available algorithms
 * @author Artem R. Romanenko
 * @version 14/11/2017
 */
public class SantuarioMessageDigestProvider implements MessageDigestEngineProvider {


    private final String messageDigestProvider;

    /**
     * Initializes a new instance that will use the specified JCE provider to get
     * MessageDigest instances.
     *
     * @param messageDigestProvider the JCE provider for MessageDigest
     * @throws NoSuchProviderException if the JCE provider is not installed
     */
    public SantuarioMessageDigestProvider(String messageDigestProvider) throws NoSuchProviderException {
        if (null == messageDigestProvider) {
            throw new NullPointerException("Message digest provider cannot be null");
        }

        if (Security.getProvider(messageDigestProvider) == null) {
            throw new NoSuchProviderException(messageDigestProvider);
        }

        this.messageDigestProvider = messageDigestProvider;
    }

    /**
     * Initializes a new instance that will get MessageDigests without specifying
     * a JCE provider.
     */
    public SantuarioMessageDigestProvider() {
        this.messageDigestProvider = null;
    }


    @Override
    public MessageDigest getEngine(String digestAlgorithmURI) throws UnsupportedAlgorithmException {

        String digestAlgorithmName = JCEMapper.translateURItoJCEID(digestAlgorithmURI);
        if (null == digestAlgorithmName) {
            throw new UnsupportedAlgorithmException("Digest algorithm not supported by the provider", digestAlgorithmURI);
        }
        try {
            return this.messageDigestProvider == null ?
                    MessageDigest.getInstance(digestAlgorithmName) :
                    MessageDigest.getInstance(digestAlgorithmName, this.messageDigestProvider);
        } catch (NoSuchAlgorithmException nsae) {
            throw new UnsupportedAlgorithmException(nsae.getMessage(), digestAlgorithmURI, nsae);
        } catch (NoSuchProviderException nspe) {
            // We checked that the provider existed on construction, but throw anyway
            throw new UnsupportedAlgorithmException("Provider not available", digestAlgorithmURI, nspe);
        }
    }
}
