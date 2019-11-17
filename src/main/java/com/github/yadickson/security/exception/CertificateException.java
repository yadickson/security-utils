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
package com.github.yadickson.security.exception;

/**
 * Handlerr class exception.
 *
 * @author Yadickson Soto
 */
@SuppressWarnings({"serial"})
public final class CertificateException extends Exception {

    /**
     * Class constructor.
     * @param message message.
     * @param cause cause.
     */
    public CertificateException(
            final String message,
            final Throwable cause
    ) {
        super(message, cause);
    }
}
