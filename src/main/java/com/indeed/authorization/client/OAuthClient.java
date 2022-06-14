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

import com.indeed.authorization.client.exceptions.OAuthBadResponseException;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import java.io.IOException;
import java.util.Objects;

public abstract class OAuthClient {
    public static final String DEFAULT_ISSUER_URL = "https://secure.indeed.com";
    public static final String DEFAULT_JWKS_URL = "https://secure.indeed.com/.well-known/keys";
    public static final Integer DEFAULT_CONNECTION_TIMEOUT = 5000;
    public static final String EMPLOYER_PARAM_KEY = "employer";
    protected final OIDCProviderMetadata oidcProviderMetadata;
    protected ClientAuthentication clientAuthentication;

    public OAuthClient(
            final String clientId,
            final String clientSecret,
            final String hostname,
            final int timeout)
            throws GeneralException, IOException {
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(clientSecret, "clientSecret must not be null");
        Objects.requireNonNull(hostname, "hostname must not be null");
        this.clientAuthentication =
                new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
        this.oidcProviderMetadata =
                OIDCProviderMetadata.resolve(new Issuer(hostname), timeout, timeout);
    }

    protected HTTPResponse executeRequest(final AbstractRequest request)
            throws OAuthBadResponseException {
        try {
            return request.toHTTPRequest().send();
        } catch (final IOException e) {
            throw new OAuthBadResponseException(e);
        }
    }

    protected OIDCTokenResponse getOIDCTokenResponse(final HTTPResponse httpResponse)
            throws OAuthBadResponseException {
        final OIDCTokenResponse tokenResponse;

        try {
            tokenResponse = OIDCTokenResponse.parse(httpResponse);
        } catch (final ParseException e) {
            throw new OAuthBadResponseException(e);
        }

        if (!tokenResponse.indicatesSuccess()) {
            throw new OAuthBadResponseException(tokenResponse.toErrorResponse());
        }
        return tokenResponse.toSuccessResponse();
    }
}
