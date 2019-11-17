/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.exception;

/**
 * Clase para el manejo de excepciones por procesamiento de certificado.
 *
 * @author Yadickson Soto
 */
@SuppressWarnings({"serial"})
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
