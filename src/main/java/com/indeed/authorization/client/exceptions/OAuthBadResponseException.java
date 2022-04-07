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

package com.indeed.authorization.client.exceptions;

import com.nimbusds.oauth2.sdk.ErrorResponse;

public class OAuthBadResponseException extends Exception {
    public OAuthBadResponseException() {}

    public OAuthBadResponseException(final Throwable throwable) {
        super(throwable);
    }

    public OAuthBadResponseException(final ErrorResponse errorResponse) {
        super(buildErrorMessage(errorResponse));
    }

    private static String buildErrorMessage(final ErrorResponse errorResponse) {
        return errorResponse.getErrorObject().getCode()
                + ": "
                + errorResponse.getErrorObject().getURI().toString()
                + " "
                + errorResponse.getErrorObject().getHTTPStatusCode()
                + " "
                + errorResponse.getErrorObject().getDescription();
    }
}
