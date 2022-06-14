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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.indeed.authorization.client.common.IndeedPrompt.PROMPT_KEY;

/**
 * <a
 * href="https://developer.indeed.com/docs/authorization/3-legged-oauth">https://developer.indeed.com/docs/authorization/3-legged-oauth</a>
 */
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
     * <a
     * href="https://developer.indeed.com/docs/authorization/3-legged-oauth#get-a-client-id-and-secret">https://developer.indeed.com/docs/authorization/3-legged-oauth#get-a-client-id-and-secret</a>
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
        final ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        final AuthorizationRequest.Builder authorizationRequestBuilder =
                new AuthorizationRequest.Builder(responseType, clientAuthentication.getClientID());
        final AuthorizationRequest request =
                authorizationRequestBuilder
                        .scope(new IndeedScope(scopes))
                        .state(new State(state))
                        .redirectionURI(new URI(redirectUrl))
                        .endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI())
                        .customParameter(PROMPT_KEY, prompt == null ? null : prompt.toString())
                        .build();
        return request.toURI();
    }

    /**
     * <a
     * href="https://developer.indeed.com/docs/authorization/3-legged-oauth#request-your-users-access-token">https://developer.indeed.com/docs/authorization/3-legged-oauth#request-your-users-access-token</a>
     *
     * @param code The authorization code. It is valid for 10 minutes from the time when you have
     *     received it. Must not be null.
     * @param redirectUrl This is the page on your site that captures the authorization code. It
     *     must match one of the redirect URLs registered with your application. Must not be null.
     * @return OIDCTokens
     * @throws OAuthBadResponseException If the response is not 2xx
     * @throws URISyntaxException If the given redirect url violates RFC2396
     */
    public OIDCTokens getUserOAuthCredentials(final String code, final String redirectUrl)
            throws OAuthBadResponseException, URISyntaxException {
        Objects.requireNonNull(code, "code must not be null");
        Objects.requireNonNull(redirectUrl, "redirectUrl must not be null");
        final AuthorizationCodeGrant authorizationCodeGrant =
                new AuthorizationCodeGrant(new AuthorizationCode(code), new URI(redirectUrl));
        final TokenRequest tokenRequest =
                new TokenRequest(
                        oidcProviderMetadata.getTokenEndpointURI(),
                        clientAuthentication,
                        authorizationCodeGrant);
        final HTTPResponse httpResponse = executeRequest(tokenRequest);
        final OIDCTokenResponse oidcTokenResponse = getOIDCTokenResponse(httpResponse);
        return oidcTokenResponse.getOIDCTokens();
    }

    /**
     * <a
     * href="https://developer.indeed.com/docs/authorization/3-legged-oauth#display-the-indeed-employer-selection-screen">https://developer.indeed.com/docs/authorization/3-legged-oauth#display-the-indeed-employer-selection-screen</a>
     *
     * @param code The authorization code. It is valid for 10 minutes from the time when you have
     *     received it. Must not be null.
     * @param redirectUrl This is the page on your site that captures the authorization code. It
     *     must match one of the redirect URLs registered with your application. Must not be null.
     * @param employerId The id that represents the employer the user has selected. Must not be
     *     null.
     * @return OIDCTokens
     * @throws OAuthBadResponseException If the response is not 2xx
     * @throws URISyntaxException If the given redirect url violates RFC2396
     */
    public OIDCTokens getEmployerOAuthCredentials(
            final String code, final String redirectUrl, final String employerId)
            throws URISyntaxException, OAuthBadResponseException {
        Objects.requireNonNull(code, "code must not be null");
        Objects.requireNonNull(redirectUrl, "redirectUrl must not be null");
        Objects.requireNonNull(employerId, "employerId must not be null");
        final AuthorizationCodeGrant authorizationCodeGrant =
                new AuthorizationCodeGrant(new AuthorizationCode(code), new URI(redirectUrl));
        final Map<String, List<String>> employerParam =
                Collections.singletonMap(EMPLOYER_PARAM_KEY, Collections.singletonList(employerId));
        final TokenRequest tokenRequest =
                new TokenRequest(
                        oidcProviderMetadata.getTokenEndpointURI(),
                        clientAuthentication,
                        authorizationCodeGrant,
                        null,
                        null,
                        employerParam);
        final HTTPResponse httpResponse = executeRequest(tokenRequest);
        final OIDCTokenResponse oidcTokenResponse = getOIDCTokenResponse(httpResponse);
        return oidcTokenResponse.getOIDCTokens();
    }

    /**
     * <a
     * href="https://developer.indeed.com/docs/authorization/3-legged-oauth#refresh-your-token">https://developer.indeed.com/docs/authorization/3-legged-oauth#refresh-your-token</a>
     *
     * @param refreshToken The refresh token returned with your user's access token. Must not be
     *     null.
     * @return OIDCTokens
     * @throws OAuthBadResponseException If the response is not 2xx
     */
    public OIDCTokens refreshOAuthCredentials(final String refreshToken)
            throws OAuthBadResponseException {
        Objects.requireNonNull(refreshToken, "refreshToken must not be null");
        final RefreshTokenGrant refreshTokenGrant =
                new RefreshTokenGrant(new RefreshToken(refreshToken));
        final TokenRequest tokenRequest =
                new TokenRequest(
                        oidcProviderMetadata.getTokenEndpointURI(),
                        clientAuthentication,
                        refreshTokenGrant);
        final HTTPResponse httpResponse = executeRequest(tokenRequest);
        final OIDCTokenResponse oidcTokenResponse = getOIDCTokenResponse(httpResponse);
        return oidcTokenResponse.getOIDCTokens();
    }
}
