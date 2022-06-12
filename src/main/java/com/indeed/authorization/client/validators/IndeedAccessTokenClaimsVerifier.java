package com.indeed.authorization.client.validators;

import com.indeed.authorization.client.claims.IndeedAccessTokenClaimsSet;
import com.indeed.authorization.client.exceptions.AccessTokenExpiredExceptionBad;
import com.indeed.authorization.client.exceptions.BadIndeedAccessTokenException;
import com.indeed.authorization.client.exceptions.InvalidAuthorizedPartyExceptionBad;
import com.indeed.authorization.client.exceptions.InvalidIssuerExceptionBad;
import com.indeed.authorization.client.exceptions.InvalidScopesExceptionBad;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

import java.util.Arrays;
import java.util.HashSet;

import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimsSet.AZP_CLAIM_NAME;
import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimsSet.EXP_CLAIM_NAME;
import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimsSet.SCOPE_CLAIM_DELIMITER;
import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimsSet.SCOPE_CLAIM_NAME;

public class IndeedAccessTokenClaimsVerifier
        implements JWTClaimsSetVerifier<JWKSecurityContext>, ClockSkewAware {
    private static final String ERROR_MESSAGE_FORMATTER = "expected: %s\nactual: %s";

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

    /**
     * Verifies selected or all claims from the specified JWT claims set.
     *
     * @param claimsSet The JWT claims set. Not null.
     * @throws BadIndeedAccessTokenException If the access token is invalid and/or missing claims
     * @throws InvalidIssuerExceptionBad If the iss claim is invalid
     * @throws InvalidAuthorizedPartyExceptionBad If the azp claim is invalid
     * @throws InvalidScopesExceptionBad If all the required scopes are not granted
     * @throws AccessTokenExpiredExceptionBad If the token is expired
     */
    @Override
    public void verify(final JWTClaimsSet claimsSet, final JWKSecurityContext context)
            throws BadIndeedAccessTokenException {
        this.verifyInternal(new IndeedAccessTokenClaimsSet(claimsSet));
    }

    /**
     * Verifies selected or all claims from the specified JWT claims set.
     *
     * @param claimsSet The JWT claims set. Not null.
     * @throws InvalidIssuerExceptionBad If the iss claim is invalid
     * @throws InvalidAuthorizedPartyExceptionBad If the azp claim is invalid
     * @throws InvalidScopesExceptionBad If all the required scopes are not granted
     * @throws AccessTokenExpiredExceptionBad If the token is expired
     */
    private void verifyInternal(final IndeedAccessTokenClaimsSet claimsSet)
            throws InvalidIssuerExceptionBad, InvalidAuthorizedPartyExceptionBad,
                    InvalidScopesExceptionBad, AccessTokenExpiredExceptionBad {
        final String iss = claimsSet.getIssuer().getValue();
        if (!this.isValidIssuer(iss)) {
            throw new InvalidIssuerExceptionBad(
                    String.format(ERROR_MESSAGE_FORMATTER, this.expectedIssuer, iss));
        }

        final String azp = (String) claimsSet.getClaim(AZP_CLAIM_NAME);
        if (!isValidAuthorizedParty(azp)) {
            throw new InvalidAuthorizedPartyExceptionBad(
                    String.format(ERROR_MESSAGE_FORMATTER, this.expectedClientID, azp));
        }

        final String scope = (String) claimsSet.getClaim(SCOPE_CLAIM_NAME);
        if (!this.areScopesGranted(scope)) {
            throw new InvalidScopesExceptionBad(
                    String.format(
                            ERROR_MESSAGE_FORMATTER, Arrays.toString(this.expectedScopes), scope));
        }

        final long exp = (long) claimsSet.getClaim(EXP_CLAIM_NAME);
        if (this.isExpired(exp)) {
            throw new AccessTokenExpiredExceptionBad(
                    String.format(ERROR_MESSAGE_FORMATTER, System.currentTimeMillis(), exp));
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
}
