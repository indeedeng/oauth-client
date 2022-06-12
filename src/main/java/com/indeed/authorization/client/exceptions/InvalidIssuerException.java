package com.indeed.authorization.client.exceptions;

public class InvalidIssuerException extends IndeedAccessTokenException {
    public InvalidIssuerException(final String message) {
        super(message);
    }

    public InvalidIssuerException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
