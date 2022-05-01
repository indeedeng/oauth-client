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

package com.indeed.authorization.client.common;

/**
 * @see com.nimbusds.openid.connect.sdk.Prompt
 */
public class IndeedPrompt {
    public static final String PROMPT_KEY = "prompt";

    /**
     * Enumeration of the prompt types.
     */
    public enum Type {
        /**
         * The authorisation server must prompt the end-user to select an employer account. This
         * allows a user who has multiple accounts at the authorisation server to select amongst the
         * multiple accounts that they may have current sessions for.
         */
        SELECT_EMPLOYER;

        /**
         * Returns the string identifier of this prompt type.
         *
         * @return The string identifier.
         */
        @Override
        public String toString() {

            return super.toString().toLowerCase();
        }
    }
}
