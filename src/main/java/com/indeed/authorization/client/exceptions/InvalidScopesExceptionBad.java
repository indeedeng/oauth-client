package com.indeed.authorization.client.exceptions;

public class InvalidScopesExceptionBad extends BadIndeedAccessTokenException {
    public InvalidScopesExceptionBad(final String message) {
        super(message);
    }

    public InvalidScopesExceptionBad(final String message, final Throwable cause) {
        super(message, cause);
    }
}
