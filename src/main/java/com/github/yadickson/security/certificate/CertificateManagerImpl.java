/*
 * Copyright (C) 2019 Yadickson Soto
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.github.yadickson.security.certificate;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang.StringUtils;

import com.github.yadickson.security.exception.CertificateException;

/**
 * Handler certificate class.
 *
 * @author Yadickson Soto
 */
public final class CertificateManagerImpl implements CertificateManager {

    /**
     * {@inheritDoc}
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
        } catch (java.security.cert.CertificateException
                | RuntimeException ex) {
            throw new CertificateException(
                    ex.getMessage(),
                    ex
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PrivateKey getPrivateKey(
            final InputStream stream,
            final String algorithm
    ) throws CertificateException {
        try {
            String base64 = getBase64(stream);
            byte[] bytes = DatatypeConverter.parseBase64Binary(base64);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePrivate(keySpec);
        } catch (CertificateException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | RuntimeException ex) {
            throw new CertificateException(
                    ex.getMessage(),
                    ex
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getBase64(
            final InputStream stream
    ) throws CertificateException {
        try (Scanner scanner = new Scanner(stream, "UTF-8")) {

            List<String> list = new ArrayList<>();

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (!line.startsWith("-----")) {
                    list.add(line);
                }
            }

            return StringUtils.join(list, "\n\r");
        } catch (Exception ex) {
            throw new CertificateException(
                    ex.getMessage(),
                    ex
            );
        }
    }
}
