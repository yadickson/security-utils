/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.basedos.seguridad.certificate;

import com.basedos.seguridad.exception.CertificateException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interfaz para manipular certificados.
 *
 * @author Yadickson Soto
 */
public interface Certificate {

    /**
     * Obtener clave publica.
     *
     * @param stream entrada de archivo certificado.
     * @return clave publica.
     * @throws CertificateException si existe error.
     */
    PublicKey getPublicKey(
            final InputStream stream
    ) throws CertificateException;

    /**
     * Obtener clave privada.
     *
     * @param stream entrada de archivo de clave privada.
     * @return clave privada.
     * @throws CertificateException si existe error.
     */
    PrivateKey getPrivateKey(
            final InputStream stream
    ) throws CertificateException;
}
