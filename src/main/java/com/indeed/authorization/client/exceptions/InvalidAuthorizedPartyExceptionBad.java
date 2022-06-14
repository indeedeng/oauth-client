package com.indeed.authorization.client.exceptions;

public class InvalidAuthorizedPartyExceptionBad extends BadIndeedAccessTokenException {
    public InvalidAuthorizedPartyExceptionBad(final String message) {
        super(message);
    }

    public InvalidAuthorizedPartyExceptionBad(final String message, final Throwable cause) {
        super(message, cause);
    }
}
