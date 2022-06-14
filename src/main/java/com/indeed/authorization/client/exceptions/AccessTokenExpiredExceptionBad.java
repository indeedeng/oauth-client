package com.indeed.authorization.client.exceptions;

public class AccessTokenExpiredExceptionBad extends BadIndeedAccessTokenException {
    public AccessTokenExpiredExceptionBad(final String message) {
        super(message);
    }

    public AccessTokenExpiredExceptionBad(final String message, final Throwable cause) {
        super(message, cause);
    }
}
