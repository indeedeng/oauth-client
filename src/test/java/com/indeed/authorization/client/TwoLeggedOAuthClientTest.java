package com.indeed.authorization.client;

import com.indeed.authorization.client.exceptions.OAuthBadResponseException;
import com.nimbusds.oauth2.sdk.GeneralException;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.indeed.authorization.client.TwoLeggedOAuthClient.create2LeggedOAuth2Client;
import static com.indeed.authorization.client.constants.MockDataLibrary.CLIENT_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.CLIENT_SECRET;
import static com.indeed.authorization.client.constants.MockDataLibrary.EMPLOYER_ID;
import static com.indeed.authorization.client.constants.MockDataLibrary.OIDC_TOKENS_ACCESS;
import static com.indeed.authorization.client.constants.MockDataLibrary.HOSTNAME;
import static com.indeed.authorization.client.constants.MockDataLibrary.TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.spy;

class TwoLeggedOAuthClientTest {
    private final TwoLeggedOAuthClient twoLeggedOAuthClient;

    public TwoLeggedOAuthClientTest() throws GeneralException, IOException {
        twoLeggedOAuthClient = spy(create2LeggedOAuth2Client(CLIENT_ID, CLIENT_SECRET, HOSTNAME));
    }

    @Test
    void requestAppAccessToken_SuccessResponse_NoException() throws OAuthBadResponseException {
        doReturn(OIDC_TOKENS_ACCESS).when(twoLeggedOAuthClient).executeTokenRequest(any());
        assertEquals(OIDC_TOKENS_ACCESS,
                twoLeggedOAuthClient.getAppOAuthCredentials(TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE));
    }

    @Test
    void requestAppAccessToken_Error_IdentityIntegrationException() throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(twoLeggedOAuthClient).executeTokenRequest(any());
        assertThrows(OAuthBadResponseException.class, () ->
                twoLeggedOAuthClient.getAppOAuthCredentials(TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE));
    }

    @Test
    void requestEmployerAccessToken_IdentityIntegrationException() throws OAuthBadResponseException {
        doThrow(new OAuthBadResponseException()).when(twoLeggedOAuthClient).executeTokenRequest(any());
        assertThrows(OAuthBadResponseException.class, () ->
                twoLeggedOAuthClient.getEmployerOAuthCredentials(EMPLOYER_ID, TWO_LEGGED_EMPLOYER_ACCESS_AUTH_SCOPE));
    }
}