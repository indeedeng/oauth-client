package com.indeed.authorization.client.exceptions;

public class InvalidIssuerExceptionBad extends BadIndeedAccessTokenException {
    public InvalidIssuerExceptionBad(final String message) {
        super(message);
    }

    public InvalidIssuerExceptionBad(final String message, final Throwable cause) {
        super(message, cause);
    }
}
