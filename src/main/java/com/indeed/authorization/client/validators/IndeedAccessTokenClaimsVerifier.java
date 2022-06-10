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

import java.util.Arrays;
import java.util.HashSet;

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
        final String iss = claimsSet.getIssuer().getValue();
        if (!this.isValidIssuer(iss)) {
            this.throwBadJWTException("Unexpected issuer claim", this.expectedIssuer, iss);
        }

        final String azp = (String) claimsSet.getClaim(AZP_CLAIM_NAME);
        if (!isValidAuthorizedParty(azp)) {
            this.throwBadJWTException(
                    "Unexpected authorized party claim", this.expectedClientID, azp);
        }

        final String scope = (String) claimsSet.getClaim(SCOPE_CLAIM_NAME);
        if (!this.areScopesGranted(scope)) {
            this.throwBadJWTException(
                    "Requested scope were not all granted",
                    Arrays.toString(this.expectedScopes),
                    scope);
        }

        final long exp = (long) claimsSet.getClaim(EXP_CLAIM_NAME);
        if (this.isExpired(exp)) {
            this.throwBadJWTException("Token is expired", System.currentTimeMillis(), exp);
        }
    }

    private boolean isValidIssuer(final String iss) {
        return this.expectedIssuer.getValue().equals(iss);
    }

    private boolean isValidAuthorizedParty(final String azp) {
        return this.expectedClientID.getValue().equals(azp);
    }

    private boolean areScopesGranted(final String scope) {
        return new HashSet<>(Arrays.asList(scope.split(SCOPE_CLAIM_DELIMITER)))
                .containsAll(Arrays.asList(this.expectedScopes));
    }

    private boolean isExpired(final long exp) {
        return System.currentTimeMillis() > exp;
    }

    private <T> void throwBadJWTException(
            final String description, final T expected, final T actual) throws BadJWTException {
        throw new BadJWTException(
                String.format(
                        "%s: \n" + "expected[%s]\n" + "actual[%s]", description, expected, actual));
    }
}
