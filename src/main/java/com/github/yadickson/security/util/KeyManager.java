/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.basedos.seguridad.util;

import java.io.InputStream;
import java.security.PrivateKey;

import com.basedos.seguridad.exception.CertificateException;
import java.security.PublicKey;

/**
 * Interfaz de clase para la manipulacion de clave privada.
 *
 * @author Yadickson Soto
 */
public interface KeyManager {

    /**
     * Obtener base64 del archivo de clave privada.
     *
     * @param stream contenido de archivo a manipular.
     * @return base64 procesado.
     * @throws CertificateException
     */
    String getBase64(
            final InputStream stream
    ) throws CertificateException;

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
     * @param base64 clave codificada.
     * @param algorithm algoritmo.
     * @return clave privada.
     * @throws CertificateException si exite error.
     */
    PrivateKey getPrivateKey(
            final String base64,
            final String algorithm
    ) throws CertificateException;

}
