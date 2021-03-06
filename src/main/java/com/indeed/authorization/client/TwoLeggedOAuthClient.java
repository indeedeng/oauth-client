/*
 * Copyright 2022 Indeed
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.indeed.authorization.client;

import com.indeed.authorization.client.common.IndeedScope;
import com.indeed.authorization.client.exceptions.OAuthBadResponseException;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import java.io.IOException;
import java.util.Collections;
import java.util.Objects;

public class TwoLeggedOAuthClient extends OAuthClient {

    public static TwoLeggedOAuthClient create2LeggedOAuth2Client(
            final String clientId, final String clientSecret, final String hostname)
            throws GeneralException, IOException {
        return new TwoLeggedOAuthClient(
                clientId, clientSecret, hostname, DEFAULT_CONNECTION_TIMEOUT);
    }

    public static TwoLeggedOAuthClient create2LeggedOAuth2Client(
            final String clientId,
            final String clientSecret,
            final String hostname,
            final int timeout)
            throws GeneralException, IOException {
        return new TwoLeggedOAuthClient(clientId, clientSecret, hostname, timeout);
    }

    private TwoLeggedOAuthClient(
            final String clientId,
            final String clientSecret,
            final String hostname,
            final int timeout)
            throws GeneralException, IOException {
        super(clientId, clientSecret, hostname, timeout);
    }

    /**
     * https://developer.indeed.com/docs/authorization/2-legged-oauth#get-an-access-token
     *
     * @param scopes To get a list of employer accounts associated with the user that registered the
     *     app or to get an access token for one of these associated employer accounts, pass
     *     employer_access.
     * @return OIDCTokens
     * @throws OAuthBadResponseException If the response is not 2xx
     */
    public OIDCTokens getAppOAuthCredentials(final String[] scopes)
            throws OAuthBadResponseException {
        Objects.requireNonNull(scopes, "scopes must not be null");
        return executeTokenRequest(
                new TokenRequest(
                        oidcProviderMetadata.getTokenEndpointURI(),
                        clientAuthentication,
                        new ClientCredentialsGrant(),
                        new IndeedScope(scopes)));
    }

    /**
     * https://developer.indeed.com/docs/authorization/2-legged-oauth#represent-an-employer
     *
     * @param employerID The id that represents the employer the user has selected.
     * @param scopes To get a list of employer accounts associated with the user that registered the
     *     app or to get an access token for one of these associated employer accounts, pass
     *     employer_access.
     * @return OIDCTokens
     * @throws OAuthBadResponseException If the response is not 2xx
     */
    public OIDCTokens getEmployerOAuthCredentials(final String employerID, final String[] scopes)
            throws OAuthBadResponseException {
        Objects.requireNonNull(employerID, "employerID must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        return executeTokenRequest(
                new TokenRequest(
                        oidcProviderMetadata.getTokenEndpointURI(),
                        clientAuthentication,
                        new ClientCredentialsGrant(),
                        new IndeedScope(scopes),
                        null,
                        Collections.singletonMap(
                                EMPLOYER_PARAM_KEY, Collections.singletonList(employerID))));
    }
}
