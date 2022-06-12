package com.indeed.authorization.client.exceptions;

import com.nimbusds.jwt.proc.BadJWTException;

public class IndeedAccessTokenException extends BadJWTException {
    public IndeedAccessTokenException(final String message) {
        super(message);
    }

    public IndeedAccessTokenException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
