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

import com.indeed.authorization.client.common.IndeedPrompt;
import com.indeed.authorization.client.common.IndeedScope;
import com.indeed.authorization.client.exceptions.OAuthBadResponseException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Objects;

import static com.indeed.authorization.client.common.IndeedPrompt.PROMPT_KEY;

/** https://developer.indeed.com/docs/authorization/3-legged-oauth */
public class ThreeLeggedOAuthClient extends OAuthClient {

    public static ThreeLeggedOAuthClient create3LeggedOAuth2Client(
            final String clientId, final String clientSecret, final String hostname)
            throws GeneralException, IOException {
        return new ThreeLeggedOAuthClient(
                clientId, clientSecret, hostname, DEFAULT_CONNECTION_TIMEOUT);
    }

    public static ThreeLeggedOAuthClient create3LeggedOAuth2Client(
            final String clientId,
            final String clientSecret,
            final String hostname,
            final int timeout)
            throws GeneralException, IOException {
        return new ThreeLeggedOAuthClient(clientId, clientSecret, hostname, timeout);
    }

    private ThreeLeggedOAuthClient(
            final String clientId,
            final String clientSecret,
            final String hostname,
            final int timeout)
            throws GeneralException, IOException {
        super(clientId, clientSecret, hostname, timeout);
    }

    /**
     * https://developer.indeed.com/docs/authorization/3-legged-oauth#get-a-client-id-and-secret
     *
     * @param state A parameter used to prevent CSRF attacks. This can be any unique string your
     *     application creates to maintain state between the request and callback. Indeed passes
     *     this parameter back to your redirect URI. See the <a
     *     href="https://tools.ietf.org/html/rfc6819#section-4.4.1.8">RFC documentation on CSRF
     *     attack against redirect-uri</a> for more information.
     * @param scopes The permissions that the client application is requesting. <a
     *     href="https://developer.indeed.com/docs/authorization/3-legged-oauth#scopes">Scopes</a>
     *     must be space-delimited and then URL encoded so the spaces are replaced by plus signs +.
     * @param prompt Displays to the authorizing user an Indeed employer selection screen, from
     *     which the user chooses the employer account assigned to your access token. To do this,
     *     add the prompt=select_employer parameter to the authorization link, and include the
     *     employer_access scope. See <a
     *     href="https://developer.indeed.com/docs/authorization/3-legged-oauth#prompt">Display the
     *     Indeed employer selection screen</a> for details.
     * @param redirectUrl This is the page on your site that captures the authorization code. It
     *     must match one of the redirect URLs registered with your application.
     * @return The authorization url to request for user's authorization.
     * @throws URISyntaxException If the given redirect url violates RFC2396
     */
    public URI getAuthorizeUrl(
            final String state,
            final String[] scopes,
            final IndeedPrompt.Type prompt,
            final String redirectUrl)
            throws URISyntaxException {
        Objects.requireNonNull(redirectUrl, "redirectUrl must not be null");
        final AuthorizationRequest request =
                new AuthorizationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                clientAuthentication.getClientID())
                        .scope(new IndeedScope(scopes))
                        .state(new State(state))
                        .redirectionURI(new URI(redirectUrl))
                        .endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI())
                        .customParameter(PROMPT_KEY, prompt == null ? null : prompt.toString())
                        .build();
        return request.toURI();
    }

    /**
     * https://developer.indeed.com/docs/authorization/3-legged-oauth#request-your-users-access-token
     *
     * @param code The authorization code. It is valid for 10 minutes from the time when you have
     *     received it.
     * @param redirectUrl This is the page on your site that captures the authorization code. It
     *     must match one of the redirect URLs registered with your application.
     * @return OIDCTokens
     * @throws OAuthBadResponseException If the response is not 2xx
     * @throws URISyntaxException If the given redirect url violates RFC2396
     */
    public OIDCTokens getUserOAuthCredentials(final String code, final String redirectUrl)
            throws OAuthBadResponseException, URISyntaxException {
        Objects.requireNonNull(code, "code must not be null");
        return executeTokenRequest(
                new TokenRequest(
                        oidcProviderMetadata.getTokenEndpointURI(),
                        clientAuthentication,
                        new AuthorizationCodeGrant(
                                new AuthorizationCode(code), new URI(redirectUrl))));
    }

    /**
     * https://developer.indeed.com/docs/authorization/3-legged-oauth#display-the-indeed-employer-selection-screen
     *
     * @param code The authorization code. It is valid for 10 minutes from the time when you have
     *     received it.
     * @param employerId The id that represents the employer the user has selected.
     * @return OIDCTokens
     * @throws OAuthBadResponseException If the response is not 2xx
     * @throws URISyntaxException If the given redirect url violates RFC2396
     */
    public OIDCTokens getEmployerOAuthCredentials(
            final String code, final String redirectUrl, final String employerId)
            throws URISyntaxException, OAuthBadResponseException {
        Objects.requireNonNull(code, "code must not be null");
        Objects.requireNonNull(employerId, "employerId must not be null");
        return executeTokenRequest(
                new TokenRequest(
                        oidcProviderMetadata.getTokenEndpointURI(),
                        clientAuthentication,
                        new AuthorizationCodeGrant(
                                new AuthorizationCode(code), new URI(redirectUrl)),
                        null,
                        null,
                        Collections.singletonMap(
                                EMPLOYER_PARAM_KEY, Collections.singletonList(employerId))));
    }

    /**
     * https://developer.indeed.com/docs/authorization/3-legged-oauth#refresh-your-token
     *
     * @param refreshToken The refresh token returned with your user's access token
     * @return OIDCTokens
     * @throws OAuthBadResponseException If the response is not 2xx
     */
    public OIDCTokens refreshOAuthCredentials(final String refreshToken)
            throws OAuthBadResponseException {
        Objects.requireNonNull(refreshToken, "refreshToken must not be null");
        return executeTokenRequest(
                new TokenRequest(
                        oidcProviderMetadata.getTokenEndpointURI(),
                        clientAuthentication,
                        new RefreshTokenGrant(new RefreshToken(refreshToken))));
    }
}
