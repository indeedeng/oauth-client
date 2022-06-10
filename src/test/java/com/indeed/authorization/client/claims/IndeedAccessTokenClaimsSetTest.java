package com.indeed.authorization.client.claims;

import com.nimbusds.oauth2.sdk.ParseException;
import org.junit.jupiter.api.Test;

import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.ACCESS_TOKEN_JWT_CLAIMS_SET;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.EMPTY_JWT_CLAIM_SET;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.EXPECTED_ACCESS_TOKEN_STANDARD_CLAIM_SET;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IndeedAccessTokenClaimsSetTest {
    @Test
    public void getStandardClaimNames_getNoExceptions() {
        assertTrue(
                IndeedAccessTokenClaimsSet.getStandardClaimNames()
                        .containsAll(EXPECTED_ACCESS_TOKEN_STANDARD_CLAIM_SET));
    }

    @Test
    public void createIndeedAccessTokenClaimSet_withValidClaimSet_getNoExceptions() {
        assertDoesNotThrow(() -> new IndeedAccessTokenClaimsSet(ACCESS_TOKEN_JWT_CLAIMS_SET));
    }

    @Test
    public void createIndeedAccessTokenClaimSet_withEmptyClaimSet_getNoExceptions() {
        assertThrows(
                ParseException.class, () -> new IndeedAccessTokenClaimsSet(EMPTY_JWT_CLAIM_SET));
    }
}
