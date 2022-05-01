package com.indeed.authorization.client.validators;

import com.indeed.authorization.client.claims.IndeedAccessTokenClaimSet;
import com.indeed.authorization.client.tokens.IndeedAccessToken;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.AbstractJWTValidator;

import java.net.URL;

public class IndeedAccessTokenValidator extends AbstractJWTValidator {
    private IndeedAccessTokenValidator(
            final Issuer expectedIssuer,
            final ClientID clientID,
            final JWSKeySelector jwsKeySelector) {
        super(expectedIssuer, clientID, jwsKeySelector, null);
    }

    public IndeedAccessTokenClaimSet validate(
            final IndeedAccessToken accessToken, final String[] scopes)
            throws BadJWTException, ParseException {
        final JWTClaimsSet claimsSet;

        try {
            claimsSet = accessToken.getJWTClaimsSet();
        } catch (final java.text.ParseException e) {
            throw new BadJWTException(e.getMessage(), e);
        }

        final IndeedAccessTokenClaimsVerifier verifier =
                new IndeedAccessTokenClaimsVerifier(
                        this.getExpectedIssuer(), this.getClientID(), scopes, getMaxClockSkew());
        verifier.verify(claimsSet, null);
        return new IndeedAccessTokenClaimSet(claimsSet);
    }

    public static IndeedAccessTokenValidator create(
            final Issuer issuer, final URL jwkSetUrl, final ClientID clientID) {
        if (jwkSetUrl == null) {
            throw new IllegalArgumentException("The expected jwkSetUrl must not be null");
        }
        return new IndeedAccessTokenValidator(
                issuer,
                clientID,
                new JWSVerificationKeySelector<JWKSecurityContext>(
                        IndeedAccessToken.JWS_ALGORITHM, new RemoteJWKSet<>(jwkSetUrl)));
    }
}
