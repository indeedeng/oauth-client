package com.indeed.authorization.client.constants;

import com.indeed.authorization.client.common.IndeedPrompt;
import com.indeed.authorization.client.common.IndeedScope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

public class MockDataLibrary {
    public static final String EMPLOYER_ID = "EMPLOYER_ID";
    public static final String HOSTNAME = "https://secure.indeed.com";
    public static final String CLIENT_ID = "CLIENT_ID";
    public static final String CLIENT_SECRET = "CLIENT_SECRET";
    public static final AccessToken ACCESS_TOKEN =
            new BearerAccessToken("eyJraWQiOiI1OTdjYTgxNC0YdVBLkWfA");
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
    public static final String ERROR_CODE = "-1";
    public static final int HTTP_ERROR_CODE = 400;
    public static final String ERROR_DESCRIPTION = "Something went wrong";
    public static final String ID_TOKEN = "ID_TOKEN";
    public static final RefreshToken REFRESH_TOKEN = new RefreshToken("REFRESH_TOKEN");
    public static final String EMPTY_STRING = "";
    public static final OIDCTokens OIDC_TOKENS_ACCESS = new OIDCTokens(ACCESS_TOKEN, null);
    public static final OIDCTokens OIDC_TOKENS_ACCESS_REFRESH =
            new OIDCTokens(ACCESS_TOKEN, REFRESH_TOKEN);
    public static final OIDCTokens OIDC_TOKENS_ID_ACCESS_REFRESH =
            new OIDCTokens(ID_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN);
    public static final OIDCTokens OIDC_TOKENS_ID_ACCESS =
            new OIDCTokens(ID_TOKEN, ACCESS_TOKEN, null);
}
