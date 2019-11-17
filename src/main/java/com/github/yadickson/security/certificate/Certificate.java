/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.certificate;

import com.github.yadickson.security.exception.CertificateException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface to handler certificates.
 *
 * @author Yadickson Soto
 */
public interface Certificate {

    /**
     * Getter public key.
     *
     * @param stream certificate input stream.
     * @return public key.
     * @throws CertificateException if error.
     */
    PublicKey getPublicKey(
            final InputStream stream
    ) throws CertificateException;

    /**
     * Getter private key.
     *
     * @param stream certificate input stream.
     * @return private key.
     * @throws CertificateException if error.
     */
    PrivateKey getPrivateKey(
            final InputStream stream
    ) throws CertificateException;
}
