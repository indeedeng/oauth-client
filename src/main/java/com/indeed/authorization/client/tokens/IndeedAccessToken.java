package com.indeed.authorization.client.tokens;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import java.text.ParseException;

public class IndeedAccessToken extends BearerAccessToken implements JWT {
    public static final JWSAlgorithm JWS_ALGORITHM = JWSAlgorithm.ES256;
    private final JWT jwt;

    public IndeedAccessToken(final String accessToken) throws ParseException {
        super(accessToken, 0L, null, null);
        this.jwt = JWTParser.parse(this.getValue());
    }

    public JWT getJwt() {
        return this.jwt;
    }

    @Override
    public Header getHeader() {
        return this.jwt.getHeader();
    }

    @Override
    public JWTClaimsSet getJWTClaimsSet() throws ParseException {
        return this.jwt.getJWTClaimsSet();
    }

    @Override
    public Base64URL[] getParsedParts() {
        return this.jwt.getParsedParts();
    }

    @Override
    public String getParsedString() {
        return this.jwt.getParsedString();
    }

    @Override
    public String serialize() {
        return this.jwt.serialize();
    }
}
