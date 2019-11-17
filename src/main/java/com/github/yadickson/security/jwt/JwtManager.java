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
package com.github.yadickson.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import com.github.yadickson.security.exception.CertificateException;

/**
 * Interface to manage jwt.
 *
 * @author Yadickson Soto
 */
public interface JwtManager {

    /**
     * Create token.
     *
     * @param privateKey private key.
     * @param signature signature algorithm.
     * @param subject subject.
     * @param map map information.
     * @param expirationTime the expiration time on minutes, if (0) zero don't
     * expire.
     * @return new token.
     * @throws CertificateException if error.
     */
    String createToken(
            final PrivateKey privateKey,
            final SignatureAlgorithm signature,
            final String subject,
            final Map<String, Object> map,
            final int expirationTime)
            throws CertificateException;

    /**
     * Getter claims from token.
     *
     * @param jwt token.
     * @param publicKey public key.
     * @return claims.
     * @throws CertificateException if error.
     */
    Claims getClaims(
            final String jwt,
            final PublicKey publicKey)
            throws CertificateException;
}
