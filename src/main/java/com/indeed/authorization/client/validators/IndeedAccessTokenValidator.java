package com.indeed.authorization.client.validators;

import com.indeed.authorization.client.claims.IndeedAccessTokenClaimsSet;
import com.indeed.authorization.client.exceptions.BadIndeedAccessTokenException;
import com.indeed.authorization.client.tokens.IndeedAccessToken;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
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

    /**
     * Validates the access token against the expected scopes.
     *
     * @param accessToken The generated access token. Must not be null.
     * @param expectedScopes The expected scopes to the access token. Must not be null.
     * @return {@link IndeedAccessTokenClaimsSet}
     * @throws BadIndeedAccessTokenException Access token is invalid and/or missing claims
     */
    public IndeedAccessTokenClaimsSet validate(
            final IndeedAccessToken accessToken, final String[] expectedScopes)
            throws BadJWTException {
        if (accessToken == null) {
            throw new IllegalArgumentException("The access token issuer must not be null");
        }

        final JWTClaimsSet claimsSet;

        try {
            claimsSet = accessToken.getJWTClaimsSet();
        } catch (final java.text.ParseException e) {
            throw new BadIndeedAccessTokenException(e.getMessage(), e);
        }

        final IndeedAccessTokenClaimsVerifier verifier =
                new IndeedAccessTokenClaimsVerifier(
                        this.getExpectedIssuer(),
                        this.getClientID(),
                        expectedScopes,
                        getMaxClockSkew());
        verifier.verify(claimsSet, null);
        return new IndeedAccessTokenClaimsSet(claimsSet);
    }

    /**
     * Create an {@link IndeedAccessTokenValidator} Object.
     *
     * @param issuer Indeed's issuer. Must not be null. (ie. <a
     *     href="https://secure.indeed.com">https://secure.indeed.com</a>
     * @param jwkSetUrl The key selector for JWS verification. Must not be null.
     * @param clientID The client ID. Must not be null.
     * @return IllegalArgumentException Invalid arguments
     */
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
