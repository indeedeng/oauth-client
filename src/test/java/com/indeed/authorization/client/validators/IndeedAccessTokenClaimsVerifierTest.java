package com.indeed.authorization.client.validators;

import com.nimbusds.jwt.proc.BadJWTException;
import org.junit.jupiter.api.Test;

import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.ACCESS_TOKEN_JWT_CLAIMS_SET;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.CLIENT_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.EMPTY_JWT_CLAIM_SET;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.EXPECTED_SCOPES;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.ISSUER;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IndeedAccessTokenClaimsVerifierTest {
    private final IndeedAccessTokenClaimsVerifier verifier =
            new IndeedAccessTokenClaimsVerifier(ISSUER, CLIENT_ID, EXPECTED_SCOPES, 1);

    @Test
    public void
            createIndeedAccessTokenClaimsVerifier_withBadArguments_getIllegalArgumentException() {
        assertAll(
                () -> {
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> new IndeedAccessTokenClaimsVerifier(null, null, null, -5));
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> new IndeedAccessTokenClaimsVerifier(ISSUER, null, null, -5));
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> new IndeedAccessTokenClaimsVerifier(ISSUER, CLIENT_ID, null, -5));
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    new IndeedAccessTokenClaimsVerifier(
                                            ISSUER, CLIENT_ID, EXPECTED_SCOPES, -5));
                });
    }

    @Test
    public void createIndeedAccessTokenClaimsVerifier_withValidArguments_getNoException() {
        assertDoesNotThrow(
                () -> new IndeedAccessTokenClaimsVerifier(ISSUER, CLIENT_ID, EXPECTED_SCOPES, 1));
    }

    @Test
    public void setMaxClockSkew_withNegativeClockSkews_getIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> this.verifier.setMaxClockSkew(-5));
    }

    @Test
    public void verify_withExpiredClaimSet_getwBadJWTException() {
        assertThrows(
                BadJWTException.class,
                () -> this.verifier.verify(ACCESS_TOKEN_JWT_CLAIMS_SET, null));
    }

    @Test
    public void verify_withInvalidClaimSet_getBadJWTException() {
        assertThrows(BadJWTException.class, () -> this.verifier.verify(EMPTY_JWT_CLAIM_SET, null));
    }
}
