/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.certificate.ec;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.springframework.stereotype.Component;

import com.github.yadickson.security.certificate.Certificate;
import com.github.yadickson.security.exception.CertificateException;
import org.springframework.beans.factory.annotation.Autowired;
import com.github.yadickson.security.util.KeyManager;

/**
 * Clase para manipulacion de certificados RSA.
 *
 * @author Yadickson Soto
 */
@Component
public final class ECCertificateImpl implements Certificate {

    /**
     * Utilitario para obtener la clave privada.
     */
    @Autowired
    private KeyManager manager;

    /**
     * Obtener clave publica.
     *
     * @param stream entrada de archivo certificado.
     * @return clave publica.
     * @throws CertificateException if error.
     */
    @Override
    public PublicKey getPublicKey(
            final InputStream stream
    ) throws CertificateException {
        return manager.getPublicKey(stream);
    }

    /**
     * Obtener clave privada.
     *
     * @param stream entrada de archivo privado.
     * @return clave privada.
     * @throws CertificateException if error.
     */
    @Override
    public PrivateKey getPrivateKey(
            final InputStream stream
    ) throws CertificateException {
        String b64 = manager.getBase64(stream);
        return manager.getPrivateKey(b64, "EC");
    }

}
