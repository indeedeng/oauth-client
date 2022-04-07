package com.indeed.authorization.client.constants;

import com.indeed.authorization.client.common.IndeedPrompt;
import com.indeed.authorization.client.common.IndeedScope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

public class MockDataLibrary {
    public final static String EMPLOYER_ID = "EMPLOYER_ID";
    public final static String HOSTNAME = "https://secure.indeed.com";
    public final static String CLIENT_ID = "CLIENT_ID";
    public final static String CLIENT_SECRET = "CLIENT_SECRET";
    public final static AccessToken ACCESS_TOKEN = new BearerAccessToken("eyJraWQiOiI1OTdjYTgxNC0YdVBLkWfA");
    public final static String REDIRECT_URI = "https://www.acerecruitersllc.com/oauth/indeed";
    public final static IndeedPrompt.Type NULL_AUTH_PROMPT = null;
    public final static IndeedPrompt.Type SELECT_EMPLOYER_AUTH_PROMPT = IndeedPrompt.Type.SELECT_EMPLOYER;
    public final static String[] THREE_LEGGED_EMPTY_AUTH_SCOPE = {};
    public final static String[] THREE_LEGGED_ALL_AUTH_SCOPES = new String[] {IndeedScope.EMAIL, IndeedScope.EMPLOYER_ACCESS, IndeedScope.OFFLINE_ACCESS};
    public final static String[] TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE = new String[] {IndeedScope.EMPLOYER_ACCESS};
    public final static String NULL_STATE = null;
    public final static String STATE = "VALID_STATE";
    public final static String CODE = "CODE";
    public final static String ERROR_CODE = "-1";
    public final static int HTTP_ERROR_CODE = 400;
    public final static String ERROR_DESCRIPTION = "Something went wrong";
    public final static String ID_TOKEN = "ID_TOKEN";
    public final static RefreshToken REFRESH_TOKEN = new RefreshToken("REFRESH_TOKEN");
    public final static String EMPTY_STRING = "";
    public final static OIDCTokens OIDC_TOKENS_ACCESS = new OIDCTokens(ACCESS_TOKEN, null);
    public final static OIDCTokens OIDC_TOKENS_ACCESS_REFRESH = new OIDCTokens(ACCESS_TOKEN, REFRESH_TOKEN);
    public final static OIDCTokens OIDC_TOKENS_ID_ACCESS_REFRESH = new OIDCTokens(ID_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN);
    public final static OIDCTokens OIDC_TOKENS_ID_ACCESS = new OIDCTokens(ID_TOKEN, ACCESS_TOKEN, null);
}
