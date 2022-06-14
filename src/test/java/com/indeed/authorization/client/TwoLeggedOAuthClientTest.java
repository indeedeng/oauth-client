package com.indeed.authorization.client;

import com.indeed.authorization.client.exceptions.OAuthBadResponseException;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.indeed.authorization.client.TwoLeggedOAuthClient.create2LeggedOAuth2Client;
import static com.indeed.authorization.client.constants.MockDataLibrary.Account.EMPLOYER_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.CLIENT_SECRET;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.HOSTNAME;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.RAW_CLIENT_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.OAuth.TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.OIDC_TOKENS_ACCESS;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.OIDC_TOKEN_RESPONSE;
import static com.indeed.authorization.client.constants.MockDataLibrary.Tokens.SUCCESS_HTTP_RESPONSE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.spy;

class TwoLeggedOAuthClientTest {
    private final TwoLeggedOAuthClient twoLeggedOAuthClient;

    public TwoLeggedOAuthClientTest() throws GeneralException, IOException {
        twoLeggedOAuthClient =
                spy(create2LeggedOAuth2Client(RAW_CLIENT_ID, CLIENT_SECRET, HOSTNAME));
    }

    @Test
    void requestAppAccessToken_withValidArgs_thenOIDCToken() throws OAuthBadResponseException {
        // Arrange
        doReturn(SUCCESS_HTTP_RESPONSE).when(twoLeggedOAuthClient).executeRequest(any());
        doReturn(OIDC_TOKEN_RESPONSE).when(twoLeggedOAuthClient).getOIDCTokenResponse(any());

        // Act
        final OIDCTokens oidcTokens =
                twoLeggedOAuthClient.getAppOAuthCredentials(TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE);

        // Assert
        assertEquals(OIDC_TOKENS_ACCESS, oidcTokens);
    }

    @Test
    void requestAppAccessToken_withResourcesFailing_thenThrowIdentityIntegrationException()
            throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(twoLeggedOAuthClient).executeRequest(any());
        assertThrows(
                OAuthBadResponseException.class,
                () ->
                        twoLeggedOAuthClient.getAppOAuthCredentials(
                                TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE));
    }

    @Test
    void requestEmployerAccessToken_withResourcesFailing_thenThrowIdentityIntegrationException()
            throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(twoLeggedOAuthClient).executeRequest(any());
        assertThrows(
                OAuthBadResponseException.class,
                () ->
                        twoLeggedOAuthClient.getEmployerOAuthCredentials(
                                EMPLOYER_ID, TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE));
    }
}
