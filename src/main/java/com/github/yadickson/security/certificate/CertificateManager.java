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
import java.security.PrivateKey;
import java.security.PublicKey;

import com.github.yadickson.security.exception.CertificateException;

/**
 * Interface to handler certificates.
 *
 * @author Yadickson Soto
 */
public interface CertificateManager {

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
     * @param algorithm algorithm.
     * @return private key.
     * @throws CertificateException if error.
     */
    PrivateKey getPrivateKey(
            final InputStream stream,
            final String algorithm
    ) throws CertificateException;

    /**
     * Getter base64 stream.
     *
     * @param stream certificate input stream.
     * @return base64 stream.
     * @throws CertificateException if error.
     */
    String getBase64(
            final InputStream stream
    ) throws CertificateException;
}
