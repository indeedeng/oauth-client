package com.indeed.authorization.client;

import com.indeed.authorization.client.exceptions.OAuthBadResponseException;
import com.nimbusds.oauth2.sdk.GeneralException;
import org.junit.jupiter.api.Test;
import org.powermock.api.mockito.PowerMockito;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static com.indeed.authorization.client.ThreeLeggedOAuthClient.create3LeggedOAuth2Client;
import static com.indeed.authorization.client.constants.MockDataLibrary.CLIENT_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.CLIENT_SECRET;
import static com.indeed.authorization.client.constants.MockDataLibrary.CODE;
import static com.indeed.authorization.client.constants.MockDataLibrary.EMPLOYER_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.EMPTY_STRING;
import static com.indeed.authorization.client.constants.MockDataLibrary.NULL_AUTH_PROMPT;
import static com.indeed.authorization.client.constants.MockDataLibrary.NULL_STATE;
import static com.indeed.authorization.client.constants.MockDataLibrary.OIDC_TOKENS_ACCESS;
import static com.indeed.authorization.client.constants.MockDataLibrary.OIDC_TOKENS_ACCESS_REFRESH;
import static com.indeed.authorization.client.constants.MockDataLibrary.OIDC_TOKENS_ID_ACCESS;
import static com.indeed.authorization.client.constants.MockDataLibrary.OIDC_TOKENS_ID_ACCESS_REFRESH;
import static com.indeed.authorization.client.constants.MockDataLibrary.HOSTNAME;
import static com.indeed.authorization.client.constants.MockDataLibrary.REDIRECT_URI;
import static com.indeed.authorization.client.constants.MockDataLibrary.REFRESH_TOKEN;
import static com.indeed.authorization.client.constants.MockDataLibrary.SELECT_EMPLOYER_AUTH_PROMPT;
import static com.indeed.authorization.client.constants.MockDataLibrary.STATE;
import static com.indeed.authorization.client.constants.MockDataLibrary.THREE_LEGGED_ALL_AUTH_SCOPES;
import static com.indeed.authorization.client.constants.MockDataLibrary.THREE_LEGGED_EMPTY_AUTH_SCOPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;

class ThreeLeggedOAuthClientTest {
    private final ThreeLeggedOAuthClient threeLeggedOAuthClient;

    public ThreeLeggedOAuthClientTest() throws GeneralException, IOException {
        threeLeggedOAuthClient = PowerMockito.spy(create3LeggedOAuth2Client(CLIENT_ID, CLIENT_SECRET, HOSTNAME));
    }

    @Test
    void getRequestAuthorizationUrl_NullOptionals_NoException() {
        assertThrows(IllegalArgumentException.class, () ->
                threeLeggedOAuthClient.getAuthorizeUrl(NULL_STATE, THREE_LEGGED_EMPTY_AUTH_SCOPE, NULL_AUTH_PROMPT, REDIRECT_URI));
    }

    @Test
    void getRequestAuthorizationUrl_SingleScope_NoException() throws URISyntaxException {
        assertThrows(IllegalArgumentException.class, () ->
                threeLeggedOAuthClient.getAuthorizeUrl(EMPTY_STRING, THREE_LEGGED_EMPTY_AUTH_SCOPE, NULL_AUTH_PROMPT, REDIRECT_URI));
    }

    @Test
    void getRequestAuthorizationUrl_ValidState_NoException() throws URISyntaxException {
        assertEquals(
                new URI("https://secure.indeed.com/oauth/v2/authorize?scope=email+employer_access+offline_access&response_type=code&redirect_uri=https%3A%2F%2Fwww.acerecruitersllc.com%2Foauth%2Findeed&state=VALID_STATE&prompt=&client_id=CLIENT_ID"),
                threeLeggedOAuthClient.getAuthorizeUrl(STATE, THREE_LEGGED_ALL_AUTH_SCOPES, NULL_AUTH_PROMPT, REDIRECT_URI));
    }

    @Test
    void getRequestAuthorizationUrl_SinglePrompt_NoException() throws URISyntaxException {
        assertEquals(
                new URI("https://secure.indeed.com/oauth/v2/authorize?scope=email+employer_access+offline_access&response_type=code&redirect_uri=https%3A%2F%2Fwww.acerecruitersllc.com%2Foauth%2Findeed&state=VALID_STATE&prompt=select_employer&client_id=CLIENT_ID"),
                threeLeggedOAuthClient.getAuthorizeUrl(STATE, THREE_LEGGED_ALL_AUTH_SCOPES, SELECT_EMPLOYER_AUTH_PROMPT, REDIRECT_URI));
    }

    @Test
    void requestAppAccessToken_SuccessResponse_NoException() throws URISyntaxException, OAuthBadResponseException {
        doReturn(OIDC_TOKENS_ACCESS).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertEquals(OIDC_TOKENS_ACCESS,
                threeLeggedOAuthClient.getUserOAuthCredentials(CODE, REDIRECT_URI));
    }

    @Test
    void requestAppAccessToken_ResponseEmptyScope_NoException() throws URISyntaxException, OAuthBadResponseException {
        doReturn(OIDC_TOKENS_ACCESS_REFRESH).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertEquals(OIDC_TOKENS_ACCESS_REFRESH,
                threeLeggedOAuthClient.getUserOAuthCredentials(CODE, REDIRECT_URI));
    }

    @Test
    void requestAppAccessToken_Error_IdentityIntegrationException() throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertThrows(OAuthBadResponseException.class, () ->
                threeLeggedOAuthClient.getUserOAuthCredentials(CODE, REDIRECT_URI));
    }

    @Test
    void requestEmployerAccessToken_SuccessResponse_NoException() throws OAuthBadResponseException, URISyntaxException {
        doReturn(OIDC_TOKENS_ID_ACCESS).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertEquals(OIDC_TOKENS_ID_ACCESS,
                threeLeggedOAuthClient.getEmployerOAuthCredentials(CODE, REDIRECT_URI, EMPLOYER_ID));
    }

    @Test
    void requestEmployerAccessToken_ResponseEmptyScope_NoException() throws OAuthBadResponseException, URISyntaxException {
        doReturn(OIDC_TOKENS_ID_ACCESS_REFRESH).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertEquals(OIDC_TOKENS_ID_ACCESS_REFRESH,
                threeLeggedOAuthClient.getEmployerOAuthCredentials(CODE, REDIRECT_URI, EMPLOYER_ID));
    }

    @Test
    void requestEmployerAccessToken_IdentityIntegrationException() throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertThrows(OAuthBadResponseException.class, () ->
                threeLeggedOAuthClient.getEmployerOAuthCredentials(CODE, REDIRECT_URI, EMPLOYER_ID));
    }

    @Test
    void requestRefreshAccessToken_SuccessResponse_NoException() throws OAuthBadResponseException {
        doReturn(OIDC_TOKENS_ACCESS_REFRESH).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertEquals(OIDC_TOKENS_ACCESS_REFRESH,
                threeLeggedOAuthClient.refreshOAuthCredentials(REFRESH_TOKEN.getValue()));
    }

    @Test
    void requestRefreshAccessToken_ResponseEmptyScope_NoException() throws OAuthBadResponseException {
        doReturn(OIDC_TOKENS_ID_ACCESS_REFRESH).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertEquals(OIDC_TOKENS_ID_ACCESS_REFRESH,
                threeLeggedOAuthClient.refreshOAuthCredentials(REFRESH_TOKEN.getValue()));
    }

    @Test
    void requestRefreshAccessToken_IdentityIntegrationException() throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(threeLeggedOAuthClient).executeTokenRequest(any());
        assertThrows(OAuthBadResponseException.class, () ->
                threeLeggedOAuthClient.refreshOAuthCredentials(REFRESH_TOKEN.getValue()));
    }
}