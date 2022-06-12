package com.indeed.authorization.client.claims;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.CommonClaimsSet;
import net.minidev.json.JSONObject;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Access token claims set, serialisable to a JSON object.
 *
 * <p>Example access token claims set:
 *
 * <pre>
 * {
 *   "sub": "user:24400320",
 *   "azp": "s6BhdRkqt3",
 *   "scope": "offline_access employer_access email",
 *   "iss": "https://secure.indeed.com",
 *   "exp": 1311281970,
 *   "iat": 1311280970
 * }
 * </pre>
 */
public class IndeedAccessTokenClaimsSet extends CommonClaimsSet {
    /** The expiration time claim name. */
    public static final String EXP_CLAIM_NAME = "exp";
    /** The scope claim name. */
    public static final String SCOPE_CLAIM_NAME = "scope";
    /** The authorized party claim name. */
    public static final String AZP_CLAIM_NAME = "azp";

    /** The names of the standard top-level access token claims. */
    private static final Set<String> STD_CLAIM_NAMES;

    static {
        final Set<String> claimNames = new HashSet<>(CommonClaimsSet.getStandardClaimNames());
        claimNames.add(EXP_CLAIM_NAME);
        claimNames.add(SCOPE_CLAIM_NAME);
        claimNames.add(AZP_CLAIM_NAME);
        STD_CLAIM_NAMES = Collections.unmodifiableSet(claimNames);
    }

    public static final String SCOPE_CLAIM_DELIMITER = " ";

    /**
     * Gets the names of the standard top-level access token claims.
     *
     * @return The names of the standard top-level access token claims (read-only set).
     */
    public static Set<String> getStandardClaimNames() {

        return STD_CLAIM_NAMES;
    }

    public IndeedAccessTokenClaimsSet(final JSONObject jsonObject) throws ParseException {

        super(jsonObject);

        if (getStringClaim(ISS_CLAIM_NAME) == null) {
            throw new ParseException("Missing iss claim");
        }

        if (getStringClaim(SUB_CLAIM_NAME) == null) {
            throw new ParseException("Missing sub claim");
        }

        if (getDateClaim(EXP_CLAIM_NAME) == null) {
            throw new ParseException("Missing exp claim");
        }

        if (getDateClaim(IAT_CLAIM_NAME) == null) {
            throw new ParseException("Missing iat claim");
        }

        if (getStringClaim(AZP_CLAIM_NAME) == null) {
            throw new ParseException("Missing azp claim");
        }

        if (getStringClaim(SCOPE_CLAIM_NAME) == null) {
            throw new ParseException("Missing scope claim");
        }

        if (getStringClaim(AUD_CLAIM_NAME) == null) {
            throw new ParseException("Missing aud claim");
        }
    }

    public IndeedAccessTokenClaimsSet(final JWTClaimsSet jwtClaimsSet) throws ParseException {
        this(JSONObjectUtils.toJSONObject(jwtClaimsSet));
    }
}
