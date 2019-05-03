/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.basedos.seguridad.exception;

/**
 * Clase para el manejo de excepciones por procesamiento de certificado.
 *
 * @author Yadickson Soto
 */
public final class CertificateException extends Exception {

    /**
     * Constructor de la clase.
     * @param message mensaje.
     * @param cause causa.
     */
    public CertificateException(
            final String message,
            final Throwable cause
    ) {
        super(message, cause);
    }
}
