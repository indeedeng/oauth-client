package com.indeed.authorization.client.tokens;

import com.indeed.authorization.client.exceptions.BadIndeedAccessTokenException;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.ACCESS_TOKEN_JWT;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.ID_TOKEN;
import static com.indeed.authorization.client.constants.MockDataLibrary.Utils.EMPTY_STRING;
import static org.junit.jupiter.api.Assertions.*;

class IndeedAccessTokenTest {
    private final IndeedAccessToken accessToken = new IndeedAccessToken(ACCESS_TOKEN_JWT);

    public IndeedAccessTokenTest() throws BadIndeedAccessTokenException {}

    @Test
    public void createIndeedAccessToken_withValidAccessToken_getReturnJwt() {
        assertDoesNotThrow(() -> new IndeedAccessToken(ACCESS_TOKEN_JWT));
    }

    @Test
    public void createIndeedAccessToken_withBlankAccessToken_getIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new IndeedAccessToken(EMPTY_STRING));
    }

    @Test
    void createIndeedAccessToken_withInvalidAccessToken_getParseException() {
        assertThrows(ParseException.class, () -> new IndeedAccessToken(ID_TOKEN));
    }
}
