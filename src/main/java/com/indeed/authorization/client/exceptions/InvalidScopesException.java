package com.indeed.authorization.client.exceptions;

public class InvalidScopesException extends BadIndeedAccessTokenException {
    public InvalidScopesException(final String message) {
        super(message);
    }

    public InvalidScopesException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
