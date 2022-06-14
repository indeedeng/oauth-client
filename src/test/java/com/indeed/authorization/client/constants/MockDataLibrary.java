package com.indeed.authorization.client.constants;

import com.indeed.authorization.client.common.IndeedPrompt;
import com.indeed.authorization.client.common.IndeedScope;
import com.indeed.authorization.client.exceptions.BadIndeedAccessTokenException;
import com.indeed.authorization.client.tokens.IndeedAccessToken;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimsSet.AZP_CLAIM_NAME;
import static com.indeed.authorization.client.claims.IndeedAccessTokenClaimsSet.SCOPE_CLAIM_NAME;

public class MockDataLibrary {
    public static class Tokens {
        public static final String EXPIRED_ACCESS_TOKEN_JWT =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyOlNVQkpFQ1RfSUQiLCJhY3QiOnsic3ViIjoiYXBwOkFEVkVSVElTRVJfSUQiLCJhcHBfYWNjb3VudCI6InVzZXI6U1VCSkVDVF9JRCJ9LCJhenAiOiJDTElFTlRfSUQiLCJzY29wZSI6Im9mZmxpbmVfYWNjZXNzIGVtcGxveWVyX2FjY2VzcyBlbWFpbCIsImlzcyI6Imh0dHBzOi8vc2VjdXJlLmluZGVlZC5jb20iLCJleHAiOjE2NTEyNjQxMDYsImlhdCI6MTY1MTI2MDUwNn0.PhqPyhY2lpxGmSf7i_FR18txWzFeH3l9MuWd1KELpJU";
        public static final String GOOD_FULL_SCOPE_ACCESS_TOKEN_JWT =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyOlNVQkpFQ1RfSUQiLCJhY3QiOnsic3ViIjoiYXBwOkFEVkVSVElTRVJfSUQiLCJhcHBfYWNjb3VudCI6InVzZXI6U1VCSkVDVF9JRCJ9LCJhenAiOiJDTElFTlRfSUQiLCJzY29wZSI6Im9mZmxpbmVfYWNjZXNzIGVtcGxveWVyX2FjY2VzcyBlbWFpbCIsImlzcyI6Imh0dHBzOi8vc2VjdXJlLmluZGVlZC5jb20iLCJleHAiOjI2NTEyNjQxMDYsImlhdCI6MTY1MTI2MDUwNn0.jZ1EtvyWpZZbLFuvcMqVEMtTTT3Sxon6_pz_9kehfbo";
        public static final String GOOD_NO_SCOPE_ACCESS_TOKEN_JWT =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyOlNVQkpFQ1RfSUQiLCJhY3QiOnsic3ViIjoiYXBwOkFEVkVSVElTRVJfSUQiLCJhcHBfYWNjb3VudCI6InVzZXI6U1VCSkVDVF9JRCJ9LCJhenAiOiJDTElFTlRfSUQiLCJzY29wZSI6IiIsImlzcyI6Imh0dHBzOi8vc2VjdXJlLmluZGVlZC5jb20iLCJleHAiOjI2NTEyNjQxMDYsImlhdCI6MTY1MTI2MDUwNn0.s6BCw8nnIlxVM4yVSAG4YPxs5N1ggcbblU2Qt94T_Jo";
        public static final IndeedAccessToken GOOD_FULL_SCOPE_ACCESS_TOKEN;
        public static final IndeedAccessToken EXPIRED_ACCESS_TOKEN;

        static {
            try {
                GOOD_FULL_SCOPE_ACCESS_TOKEN =
                        new IndeedAccessToken(GOOD_FULL_SCOPE_ACCESS_TOKEN_JWT);
                EXPIRED_ACCESS_TOKEN = new IndeedAccessToken(EXPIRED_ACCESS_TOKEN_JWT);
            } catch (final BadIndeedAccessTokenException e) {
                throw new RuntimeException(e);
            }
        }

        public static final HTTPResponse SUCCESS_HTTP_RESPONSE =
                new HTTPResponse(HTTPResponse.SC_OK);
        public static final HTTPResponse FAILED_HTTP_RESPONSE =
                new HTTPResponse(HTTPResponse.SC_SERVER_ERROR);
        public static final OIDCTokens OIDC_TOKENS_ACCESS =
                new OIDCTokens(GOOD_FULL_SCOPE_ACCESS_TOKEN, null);
        public static final OIDCTokenResponse OIDC_TOKEN_RESPONSE =
                new OIDCTokenResponse(OIDC_TOKENS_ACCESS);
        public static final String ID_TOKEN = "ID_TOKEN";
        public static final OIDCTokens OIDC_TOKENS_ID_ACCESS =
                new OIDCTokens(ID_TOKEN, GOOD_FULL_SCOPE_ACCESS_TOKEN, null);
        public static final OIDCTokenResponse OIDC_TOKEN_ID_ACCESS_RESPONSE =
                new OIDCTokenResponse(OIDC_TOKENS_ID_ACCESS);
        public static final RefreshToken REFRESH_TOKEN = new RefreshToken("REFRESH_TOKEN");
        public static final OIDCTokens OIDC_TOKENS_ID_ACCESS_REFRESH =
                new OIDCTokens(ID_TOKEN, GOOD_FULL_SCOPE_ACCESS_TOKEN, REFRESH_TOKEN);
        public static final OIDCTokenResponse REFRESHED_OIDC_TOKEN_ID_ACCESS_RESPONSE =
                new OIDCTokenResponse(OIDC_TOKENS_ID_ACCESS_REFRESH);
        public static final OIDCTokens OIDC_TOKENS_ACCESS_REFRESH =
                new OIDCTokens(GOOD_FULL_SCOPE_ACCESS_TOKEN, REFRESH_TOKEN);
        public static final OIDCTokenResponse REFRESHED_OIDC_TOKEN_ACCESS_ACCESS_RESPONSE =
                new OIDCTokenResponse(OIDC_TOKENS_ACCESS_REFRESH);
    }

    public static class OAuth {
        public static final String HOSTNAME = "https://secure.indeed.com";
        public static final String JWKS_URI = "https://secure.indeed.com/.well-known/keys";
        public static final Issuer ISSUER = new Issuer(HOSTNAME);
        public static final String RAW_CLIENT_ID = "CLIENT_ID";
        public static final ClientID CLIENT_ID = new ClientID(RAW_CLIENT_ID);
        public static final String CLIENT_SECRET = "CLIENT_SECRET";
        public static final String REDIRECT_URI = "https://www.acerecruitersllc.com/oauth/indeed";
        public static final IndeedPrompt.Type NULL_AUTH_PROMPT = null;
        public static final IndeedPrompt.Type SELECT_EMPLOYER_AUTH_PROMPT =
                IndeedPrompt.Type.SELECT_EMPLOYER;
        public static final String[] THREE_LEGGED_EMPTY_AUTH_SCOPE = {};
        public static final String[] THREE_LEGGED_ALL_AUTH_SCOPES =
                new String[] {
                    IndeedScope.EMAIL, IndeedScope.EMPLOYER_ACCESS, IndeedScope.OFFLINE_ACCESS
                };
        public static final String[] TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE =
                new String[] {IndeedScope.EMPLOYER_ACCESS};
        public static final String NULL_STATE = null;
        public static final String STATE = "VALID_STATE";
        public static final String CODE = "CODE";
        public static final String RAW_EXPECTED_SCOPES = "offline_access+employer_access+email";
        public static final String[] EXPECTED_SCOPES =
                new String[] {"offline_access", "employer_access", "email"};
        public static final String RECEIVED_SCOPES = "offline_access employer_access email";
        public static final String AUTHORIZATION_PARTY = RAW_CLIENT_ID;
        public static final JWTClaimsSet ACCESS_TOKEN_JWT_CLAIMS_SET =
                new JWTClaimsSet.Builder()
                        .expirationTime(Utils.DATE)
                        .issuer(HOSTNAME)
                        .issueTime(Utils.DATE)
                        .subject(Account.SUBJECT_ID)
                        .claim(AZP_CLAIM_NAME, AUTHORIZATION_PARTY)
                        .claim(SCOPE_CLAIM_NAME, RECEIVED_SCOPES)
                        .build();
        public static final String AUDIENCE = "AUDIENCE";
        public static final Set<String> EXPECTED_ACCESS_TOKEN_STANDARD_CLAIM_SET =
                new HashSet<>(Arrays.asList("iat", "exp", "sub", "azp", "scope", "iss"));
        public static final JWTClaimsSet EMPTY_JWT_CLAIM_SET = new JWTClaimsSet.Builder().build();
    }

    public static class Account {
        public static final String EMPLOYER_ID = "EMPLOYER_ID";
        public static final String SUBJECT_ID = "SUBJECT_ID";

        public static final UserInfo USER_INFO = new UserInfo(new Subject(SUBJECT_ID));
        public static final UserInfoSuccessResponse USER_INFO_SUCCESS_RESPONSE =
                new UserInfoSuccessResponse(USER_INFO);
    }

    public static class Error {
        public static final String ERROR_CODE = "-1";
        public static final int HTTP_ERROR_CODE = 400;
        public static final String ERROR_DESCRIPTION = "Something went wrong";
    }

    public static class Utils {
        public static final String EMPTY_STRING = "";
        public static final Date DATE = new Date(System.currentTimeMillis());
    }
}
