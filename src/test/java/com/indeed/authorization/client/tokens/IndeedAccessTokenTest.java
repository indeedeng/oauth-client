package com.indeed.authorization.client.tokens;

import com.indeed.authorization.client.exceptions.BadIndeedAccessTokenException;
import org.junit.jupiter.api.Test;

import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.EXPIRED_ACCESS_TOKEN_JWT;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.ID_TOKEN;
import static com.indeed.authorization.client.constants.MockDataLibrary.Utils.EMPTY_STRING;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IndeedAccessTokenTest {
    @Test
    public void createIndeedAccessToken_withValidAccessToken_getReturnJwt() {
        assertDoesNotThrow(() -> new IndeedAccessToken(EXPIRED_ACCESS_TOKEN_JWT));
    }

    @Test
    public void createIndeedAccessToken_withBlankAccessToken_getIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new IndeedAccessToken(EMPTY_STRING));
    }

    @Test
    void createIndeedAccessToken_withInvalidAccessToken_getBadIndeedAccessTokenException() {
        assertThrows(BadIndeedAccessTokenException.class, () -> new IndeedAccessToken(ID_TOKEN));
    }
}
