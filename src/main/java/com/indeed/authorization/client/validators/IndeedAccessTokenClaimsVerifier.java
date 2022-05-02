package com.indeed.authorization.client.validators;

import com.indeed.authorization.client.claims.IndeedAccessTokenClaimSet;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimSet.AZP_CLAIM_NAME;
import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimSet.EXP_CLAIM_NAME;
import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimSet.SCOPE_CLAIM_DELIMITER;
import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimSet.SCOPE_CLAIM_NAME;

public class IndeedAccessTokenClaimsVerifier
        implements JWTClaimsSetVerifier<JWKSecurityContext>, ClockSkewAware {
    private final Issuer expectedIssuer;
    private final ClientID expectedClientID;
    private final String[] expectedScopes;
    private int maxClockSkew;

    /**
     * Creates a new access token claims verifier.
     *
     * @param issuer The expected ID token issuer. Must not be {@code null}.
     * @param clientID The expected client ID. Must not be {@code null}.
     * @param scopes The expected scopes. Must not be {@code null}.
     * @param maxClockSkew The maximum acceptable clock skew (absolute value), in seconds. Must be
     *     zero (no clock skew) or positive integer.
     */
    public IndeedAccessTokenClaimsVerifier(
            final Issuer issuer,
            final ClientID clientID,
            final String[] scopes,
            final int maxClockSkew) {

        if (issuer == null) {
            throw new IllegalArgumentException("The expected ID token issuer must not be null");
        }
        this.expectedIssuer = issuer;

        if (clientID == null) {
            throw new IllegalArgumentException("The expected client ID must not be null");
        }
        this.expectedClientID = clientID;

        if (scopes == null) {
            throw new IllegalArgumentException("The expected scopes must not be null");
        }
        this.expectedScopes = scopes;

        setMaxClockSkew(maxClockSkew);
    }

    @Override
    public int getMaxClockSkew() {
        return this.maxClockSkew;
    }

    @Override
    public void setMaxClockSkew(final int maxClockSkewSeconds) {
        if (maxClockSkewSeconds < 0) {
            throw new IllegalArgumentException("The max clock skew must be zero or positive");
        }
        this.maxClockSkew = maxClockSkewSeconds;
    }

    @Override
    public void verify(final JWTClaimsSet claimsSet, final JWKSecurityContext context)
            throws BadJWTException {
        try {
            this.verifyInternal(new IndeedAccessTokenClaimSet(claimsSet));
        } catch (final ParseException e) {
            throw new BadJWTException(e.getMessage(), e);
        }
    }

    /**
     * Verifies selected or all claims from the specified JWT claims set.
     *
     * @param claimsSet The JWT claims set. Not null.
     * @throws BadJWTException If the JWT claims set is rejected.
     */
    private void verifyInternal(final IndeedAccessTokenClaimSet claimsSet) throws BadJWTException {
        final String actualIssuer = claimsSet.getIssuer().getValue();
        if (!this.expectedIssuer.getValue().equals(actualIssuer)) {
            throw new BadJWTException("Unexpected issuer claim: " + claimsSet.getIssuer());
        }

        final String actualAuthorizedParty = (String) claimsSet.getClaim(AZP_CLAIM_NAME);
        if (!this.expectedClientID.getValue().equals(actualAuthorizedParty)) {
            throw new BadJWTException(
                    "Unexpected authorized party claim: " + actualAuthorizedParty);
        }

        final String[] actualScopes =
                ((String) claimsSet.getClaim(SCOPE_CLAIM_NAME)).split(SCOPE_CLAIM_DELIMITER);
        if (!Arrays.deepEquals(actualScopes, this.expectedScopes)) {
            throw new BadJWTException("Unexpected scope claim: " + actualAuthorizedParty);
        }

        final Date expirationTime = new Date((long) claimsSet.getClaim(EXP_CLAIM_NAME));
        if (Date.from(Instant.now()).after(expirationTime)) {
            throw new BadJWTException("Token has expired at: " + expirationTime);
        }
    }
}
