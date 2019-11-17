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
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.github.yadickson.security.exception.CertificateException;

/**
 * Class to manage jwt.
 *
 * @author Yadickson Soto
 */
public final class JwtManagerImpl implements JwtManager {

    /**
     * {@inheritDoc}
     */
    @Override
    public String createToken(
            final PrivateKey privateKey,
            final SignatureAlgorithm signature,
            final String subject,
            final Map<String, Object> map,
            final int expirationTime)
            throws CertificateException {

        try {

            Date date = new Date();

            Calendar c = Calendar.getInstance();
            c.setTime(date);

            Claims claims = Jwts.claims().setSubject(subject);
            claims.putAll(map);

            JwtBuilder builder = Jwts
                    .builder()
                    .setClaims(claims)
                    .setId(UUID.randomUUID().toString())
                    .setIssuedAt(c.getTime())
                    .signWith(
                            signature,
                            privateKey
                    );

            if (expirationTime > 0) {

                Calendar ce = Calendar.getInstance();
                ce.setTime(date);
                ce.add(Calendar.MINUTE, expirationTime);
                builder.setExpiration(ce.getTime());
            }

            return builder.compact();

        } catch (Exception ex) {
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
    public Claims getClaims(
            final String jwt,
            final PublicKey publicKey)
            throws CertificateException {

        try {

            return Jwts
                    .parser()
                    .setSigningKey(publicKey)
                    .parseClaimsJws(jwt)
                    .getBody();

        } catch (Exception ex) {
            throw new CertificateException(
                    ex.getMessage(),
                    ex
            );
        }
    }

}
