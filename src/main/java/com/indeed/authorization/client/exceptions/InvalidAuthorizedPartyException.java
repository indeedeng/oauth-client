package com.indeed.authorization.client.exceptions;

public class InvalidAuthorizedPartyException extends BadIndeedAccessTokenException {
    public InvalidAuthorizedPartyException(final String message) {
        super(message);
    }

    public InvalidAuthorizedPartyException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
