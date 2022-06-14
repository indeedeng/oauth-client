package com.indeed.authorization.client;

import com.indeed.authorization.client.exceptions.OAuthBadResponseException;
import com.nimbusds.oauth2.sdk.GeneralException;
import org.junit.jupiter.api.Test;
import org.powermock.api.mockito.PowerMockito;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static com.indeed.authorization.client.ThreeLeggedOAuthClient.create3LeggedOAuth2Client;
import static com.indeed.authorization.client.constants.MockDataLibrary.Account.EMPLOYER_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.CLIENT_SECRET;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.CODE;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.HOSTNAME;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.NULL_AUTH_PROMPT;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.NULL_STATE;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.RAW_CLIENT_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.REDIRECT_URI;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.SELECT_EMPLOYER_AUTH_PROMPT;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.STATE;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.THREE_LEGGED_ALL_AUTH_SCOPES;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.THREE_LEGGED_EMPTY_AUTH_SCOPE;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.OIDC_TOKENS_ACCESS;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.OIDC_TOKENS_ACCESS_REFRESH;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.OIDC_TOKENS_ID_ACCESS;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.OIDC_TOKENS_ID_ACCESS_REFRESH;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.OIDC_TOKEN_ID_ACCESS_RESPONSE;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.OIDC_TOKEN_RESPONSE;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.REFRESHED_OIDC_TOKEN_ACCESS_ACCESS_RESPONSE;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.REFRESHED_OIDC_TOKEN_ID_ACCESS_RESPONSE;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.REFRESH_TOKEN;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.SUCCESS_HTTP_RESPONSE;
import static com.indeed.authorization.client.constants.MockDataLibrary.Utils.EMPTY_STRING;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;

class ThreeLeggedOAuthClientTest {
    private final ThreeLeggedOAuthClient threeLeggedOAuthClient;

    public ThreeLeggedOAuthClientTest() throws GeneralException, IOException {
        threeLeggedOAuthClient =
                PowerMockito.spy(create3LeggedOAuth2Client(RAW_CLIENT_ID, CLIENT_SECRET, HOSTNAME));
    }

    @Test
    void getRequestAuthorizationUrl_withValidArgsAndNullScope_thenThrowIllegalArgumentException() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        threeLeggedOAuthClient.getAuthorizeUrl(
                                NULL_STATE,
                                THREE_LEGGED_EMPTY_AUTH_SCOPE,
                                NULL_AUTH_PROMPT,
                                REDIRECT_URI));
    }

    @Test
    void
            getRequestAuthorizationUrl_withValidArgsAndSingleScope_thenThrowIllegalArgumentException() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        threeLeggedOAuthClient.getAuthorizeUrl(
                                EMPTY_STRING,
                                THREE_LEGGED_EMPTY_AUTH_SCOPE,
                                NULL_AUTH_PROMPT,
                                REDIRECT_URI));
    }

    @Test
    void getRequestAuthorizationUrl_withValidArgsAndValidState_thenReturnValidUri()
            throws URISyntaxException {
        assertEquals(
                new URI(
                        "https://secure.indeed.com/oauth/v2/authorize?scope=email+employer_access+offline_access&response_type=code&redirect_uri=https%3A%2F%2Fwww.acerecruitersllc.com%2Foauth%2Findeed&state=VALID_STATE&prompt=&client_id=CLIENT_ID"),
                threeLeggedOAuthClient.getAuthorizeUrl(
                        STATE, THREE_LEGGED_ALL_AUTH_SCOPES, NULL_AUTH_PROMPT, REDIRECT_URI));
    }

    @Test
    void getRequestAuthorizationUrl_withValidArgsAndSinglePrompt_thenReturnValidUri()
            throws URISyntaxException {
        assertEquals(
                new URI(
                        "https://secure.indeed.com/oauth/v2/authorize?scope=email+employer_access+offline_access&response_type=code&redirect_uri=https%3A%2F%2Fwww.acerecruitersllc.com%2Foauth%2Findeed&state=VALID_STATE&prompt=select_employer&client_id=CLIENT_ID"),
                threeLeggedOAuthClient.getAuthorizeUrl(
                        STATE,
                        THREE_LEGGED_ALL_AUTH_SCOPES,
                        SELECT_EMPLOYER_AUTH_PROMPT,
                        REDIRECT_URI));
    }

    @Test
    void requestAppAccessToken_withValidArgsAndSuccessResponse_thenReturnOIDCToken()
            throws URISyntaxException, OAuthBadResponseException {
        doReturn(SUCCESS_HTTP_RESPONSE).when(threeLeggedOAuthClient).executeRequest(any());
        doReturn(OIDC_TOKEN_RESPONSE).when(threeLeggedOAuthClient).getOIDCTokenResponse(any());
        assertEquals(
                OIDC_TOKENS_ACCESS,
                threeLeggedOAuthClient.getUserOAuthCredentials(CODE, REDIRECT_URI));
    }

    @Test
    void requestAppAccessToken_withResponseEmptyScope_thenReturnNoException()
            throws URISyntaxException, OAuthBadResponseException {
        doReturn(SUCCESS_HTTP_RESPONSE).when(threeLeggedOAuthClient).executeRequest(any());
        doReturn(REFRESHED_OIDC_TOKEN_ACCESS_ACCESS_RESPONSE)
                .when(threeLeggedOAuthClient)
                .getOIDCTokenResponse(any());
        assertEquals(
                OIDC_TOKENS_ACCESS_REFRESH,
                threeLeggedOAuthClient.getUserOAuthCredentials(CODE, REDIRECT_URI));
    }

    @Test
    void requestAppAccessToken_withFailResources_thenThrowIdentityIntegrationException()
            throws OAuthBadResponseException {
        doReturn(SUCCESS_HTTP_RESPONSE).when(threeLeggedOAuthClient).executeRequest(any());
        doThrow(new OAuthBadResponseException())
                .when(threeLeggedOAuthClient)
                .getOIDCTokenResponse(any());
        assertThrows(
                OAuthBadResponseException.class,
                () -> threeLeggedOAuthClient.getUserOAuthCredentials(CODE, REDIRECT_URI));
    }

    @Test
    void requestEmployerAccessToken_withSuccessResponses_thenReturnValidOIDCToken()
            throws OAuthBadResponseException, URISyntaxException {
        doReturn(SUCCESS_HTTP_RESPONSE).when(threeLeggedOAuthClient).executeRequest(any());
        doReturn(OIDC_TOKEN_ID_ACCESS_RESPONSE)
                .when(threeLeggedOAuthClient)
                .getOIDCTokenResponse(any());
        assertEquals(
                OIDC_TOKENS_ID_ACCESS,
                threeLeggedOAuthClient.getEmployerOAuthCredentials(
                        CODE, REDIRECT_URI, EMPLOYER_ID));
    }

    @Test
    void requestEmployerAccessToken_withResponseEmptyScope_thenReturnValidOIDCToken()
            throws OAuthBadResponseException, URISyntaxException {
        doReturn(SUCCESS_HTTP_RESPONSE).when(threeLeggedOAuthClient).executeRequest(any());
        doReturn(REFRESHED_OIDC_TOKEN_ID_ACCESS_RESPONSE)
                .when(threeLeggedOAuthClient)
                .getOIDCTokenResponse(any());
        assertEquals(
                OIDC_TOKENS_ID_ACCESS_REFRESH,
                threeLeggedOAuthClient.getEmployerOAuthCredentials(
                        CODE, REDIRECT_URI, EMPLOYER_ID));
    }

    @Test
    void requestEmployerAccessToken_withFailresources_thenThrowIdentityIntegrationException()
            throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(threeLeggedOAuthClient).executeRequest(any());
        assertThrows(
                OAuthBadResponseException.class,
                () ->
                        threeLeggedOAuthClient.getEmployerOAuthCredentials(
                                CODE, REDIRECT_URI, EMPLOYER_ID));
    }

    @Test
    void requestRefreshAccessToken_withSuccessResponses_thenReturnValidOIDCToken()
            throws OAuthBadResponseException {
        doReturn(SUCCESS_HTTP_RESPONSE).when(threeLeggedOAuthClient).executeRequest(any());
        doReturn(REFRESHED_OIDC_TOKEN_ACCESS_ACCESS_RESPONSE)
                .when(threeLeggedOAuthClient)
                .getOIDCTokenResponse(any());
        assertEquals(
                OIDC_TOKENS_ACCESS_REFRESH,
                threeLeggedOAuthClient.refreshOAuthCredentials(REFRESH_TOKEN.getValue()));
    }

    @Test
    void requestRefreshAccessToken_withResponseEmptyScope_thenReturnValidOIDCToken()
            throws OAuthBadResponseException {
        doReturn(SUCCESS_HTTP_RESPONSE).when(threeLeggedOAuthClient).executeRequest(any());
        doReturn(REFRESHED_OIDC_TOKEN_ID_ACCESS_RESPONSE)
                .when(threeLeggedOAuthClient)
                .getOIDCTokenResponse(any());
        assertEquals(
                OIDC_TOKENS_ID_ACCESS_REFRESH,
                threeLeggedOAuthClient.refreshOAuthCredentials(REFRESH_TOKEN.getValue()));
    }

    @Test
    void requestRefreshAccessToken_withFailResources_thenThrowIdentityIntegrationException()
            throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(threeLeggedOAuthClient).executeRequest(any());
        assertThrows(
                OAuthBadResponseException.class,
                () -> threeLeggedOAuthClient.refreshOAuthCredentials(REFRESH_TOKEN.getValue()));
    }
}
