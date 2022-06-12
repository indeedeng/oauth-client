package com.indeed.authorization.client.exceptions;

public class InvalidScopesException extends IndeedAccessTokenException {
    public InvalidScopesException(final String message) {
        super(message);
    }

    public InvalidScopesException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
