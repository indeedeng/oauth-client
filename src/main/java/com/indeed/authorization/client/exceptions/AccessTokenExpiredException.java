package com.indeed.authorization.client.exceptions;

public class AccessTokenExpiredException extends BadIndeedAccessTokenException {
    public AccessTokenExpiredException(final String message) {
        super(message);
    }

    public AccessTokenExpiredException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
