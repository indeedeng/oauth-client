package com.indeed.authorization.client.exceptions;

import com.nimbusds.jwt.proc.BadJWTException;

public class BadIndeedAccessTokenException extends BadJWTException {
    public BadIndeedAccessTokenException(final String message) {
        super(message);
    }

    public BadIndeedAccessTokenException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
