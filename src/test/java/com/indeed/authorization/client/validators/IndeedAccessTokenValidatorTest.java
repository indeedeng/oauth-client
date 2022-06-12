package com.indeed.authorization.client.validators;

import com.indeed.authorization.client.exceptions.BadIndeedAccessTokenException;
import com.indeed.authorization.client.tokens.IndeedAccessToken;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;

import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.CLIENT_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.EXPECTED_SCOPES;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.ISSUER;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.JWKS_URI;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.ACCESS_TOKEN;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IndeedAccessTokenValidatorTest {
    private final IndeedAccessTokenValidator validator =
            IndeedAccessTokenValidator.create(ISSUER, new URL(JWKS_URI), CLIENT_ID);
    private final IndeedAccessTokenValidator defaultValidator =
            IndeedAccessTokenValidator.create(CLIENT_ID);

    IndeedAccessTokenValidatorTest() throws MalformedURLException {}

    @Test
    public void createIndeedAccessTokenValidator_withValidArguments_getNoException() {
        assertAll(
                () -> {
                    assertDoesNotThrow(
                            () ->
                                    IndeedAccessTokenValidator.create(
                                            ISSUER, new URL(JWKS_URI), CLIENT_ID));
                    assertDoesNotThrow(() -> IndeedAccessTokenValidator.create(CLIENT_ID));
                });
    }

    @Test
    public void createIndeedAccessTokenValidator_withBadArguments_getNoException() {
        assertAll(
                () -> {
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> IndeedAccessTokenValidator.create(null, null, null));
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> IndeedAccessTokenValidator.create(null, new URL(JWKS_URI), null));
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    IndeedAccessTokenValidator.create(
                                            ISSUER, new URL(JWKS_URI), null));
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> IndeedAccessTokenValidator.create(null));
                });
    }

    @Test
    public void validate_withExpiredAccessToken_getBadJWTException() {
        assertAll(
                () -> {
                    assertThrows(
                            BadIndeedAccessTokenException.class,
                            () -> this.validator.validate(ACCESS_TOKEN, EXPECTED_SCOPES));
                    assertThrows(
                            BadIndeedAccessTokenException.class,
                            () -> this.defaultValidator.validate(ACCESS_TOKEN, EXPECTED_SCOPES));
                });
    }

    @Test
    public void validate_witInvalidAccessToken_getBadJWTException() {
        assertAll(
                () -> {
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    this.validator.validate(
                                            new IndeedAccessToken(""), EXPECTED_SCOPES));
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    this.defaultValidator.validate(
                                            new IndeedAccessToken(""), EXPECTED_SCOPES));
                });
    }
}
