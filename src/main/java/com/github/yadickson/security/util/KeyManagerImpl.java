/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.util;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

import org.springframework.stereotype.Component;

import com.github.yadickson.security.exception.CertificateException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.commons.lang.StringUtils;

/**
 *
 * Clase para la manipulacion de clave privada.
 *
 * @author Yadickson Soto
 */
@Component
public final class KeyManagerImpl implements KeyManager {

    /**
     * Obtener base64 del archivo de clave privada.
     *
     * @param stream contenido de archivo a manipular.
     * @return base64 procesado.
     * @throws CertificateException
     */
    @Override
    public String getBase64(
            final InputStream stream
    ) throws CertificateException {
        try {
            Scanner scanner = new Scanner(stream);
            List<String> list = new ArrayList<>();

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                list.add(line);
            }

            list.subList(1, list.size() - 1);

            scanner.close();

            return StringUtils.join(list, "\n\r");
        } catch (Exception ex) {
            throw new CertificateException(
                    "No es posible obtener b64 de la clave privada",
                    ex
            );
        }
    }

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

        try {
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate;
            certificate = (X509Certificate) f.generateCertificate(stream);
            return certificate.getPublicKey();
        } catch (Exception ex) {
            throw new CertificateException(
                    "No es posible generar clave publica",
                    ex
            );
        }
    }

    /**
     * Obtener clave privada.
     *
     * @param base64 clave codificada.
     * @param algorithm algoritmo.
     * @return clave privada.
     * @throws CertificateException si exite error.
     */
    @Override
    public PrivateKey getPrivateKey(
            final String base64,
            final String algorithm
    ) throws CertificateException {
        try {
            byte[] bytes = DatatypeConverter.parseBase64Binary(base64);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception ex) {
            throw new CertificateException(
                    "No es posible generar clave privada",
                    ex
            );
        }
    }
}
