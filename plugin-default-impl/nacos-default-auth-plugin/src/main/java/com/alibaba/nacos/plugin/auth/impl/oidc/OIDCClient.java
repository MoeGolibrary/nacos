/*
 * Copyright 1999-2025 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.plugin.auth.impl.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest.Builder;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Open ID Connect Client for handling Open ID Connect authentication requests and responses.
 *
 * @author Roiocam
 */
@SuppressWarnings("checkstyle:abbreviationaswordinname")
@Component
public class OIDCClient {
    
    private static final ResponseType RESPONSE_TYPE = new ResponseType(Value.CODE);
    
    private static final Logger LOGGER = LoggerFactory.getLogger(OIDCClient.class);
    
    private final OIDCConfig config;
    
    public OIDCClient(@Autowired(required = false) OIDCConfig config) {
        OIDCConfig oidcConfig;
        if (config == null) {
            String provider = OIDCConfigs.getProvider();
            if (provider == null || provider.trim().isEmpty()) {
                LOGGER.warn("No OIDC provider configured and no default configuration available.");
                oidcConfig = null;
            } else {
                try {
                    oidcConfig = OIDCConfigs.getConfiguration(provider);
                } catch (Exception e) {
                    LOGGER.error("Failed to load default OIDC configuration", e);
                    oidcConfig = null;
                }
            }
        } else {
            oidcConfig = config;
        }
        this.config = oidcConfig;
    }

    /**
     * Create an Open ID Connect Authentication Request.
     *
     * @param callbackUrl Callback url for Authorization Server
     * @return AuthenticationRequest
     */
    public AuthenticationRequest createAuthenticationRequest(String callbackUrl, String originUrl) {
        Nonce nonce = new Nonce();
        State state = new State();
        OIDCState oidcState = new OIDCState();
        oidcState.setState(state.getValue());
        oidcState.setNonce(nonce.getValue());
        oidcState.setOrigin(originUrl);
        oidcState.setCallbackUrl(callbackUrl);
        OIDCProviderMetadata providerMetadata = getProviderMetadata();
        return new Builder(RESPONSE_TYPE, getScope(), getClientId(), URI.create(callbackUrl)).endpointURI(
                providerMetadata.getAuthorizationEndpointURI()).state(oidcState.toState()).nonce(nonce).build();
    }

    /**
     * Get UserInfo from Authorization Server by exchange the authorization code.
     *
     * @param authorizationCode Authorization Code
     * @param callbackUrl       Callback URL
     * @param nonce             OriginNonce
     * @return UserInfo
     */
    public UserInfo getUserInfo(AuthorizationCode authorizationCode, String callbackUrl, String nonce) {
        OIDCProviderMetadata providerMetadata = getProviderMetadata();
        LOGGER.debug("Getting user info for authorization code");
        OIDCTokens oidcTokens = exchangeToken(authorizationCode, callbackUrl, nonce);

        UserInfo userInfo = null;
        try {
            if (oidcTokens.getIDToken() != null && oidcTokens.getIDToken().getJWTClaimsSet() != null) {
                userInfo = new UserInfo(oidcTokens.getIDToken().getJWTClaimsSet());
            }
        } catch (java.text.ParseException e) {
            throw new IllegalStateException("Parsing ID token failed", e);
        }
        if (userInfo == null || hasEnoughInfo(userInfo)) {
            BearerAccessToken accessToken = oidcTokens.getBearerAccessToken();
            if (accessToken == null) {
                throw new IllegalStateException("Bearer access token is missing after token exchange");
            }

            UserInfoResponse userInfoResponse = exchangeUserInfo(providerMetadata.getUserInfoEndpointURI(), accessToken);
            if (userInfoResponse instanceof UserInfoErrorResponse) {
                ErrorObject errorObject = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
                if (errorObject == null || errorObject.getCode() == null) {
                    throw new IllegalStateException("UserInfo request failed: No error code returned "
                            + "(identity provider might be unreachable)");
                } else {
                    throw new IllegalStateException("UserInfo request failed: " + errorObject.toJSONObject());
                }
            }
            userInfo = ((UserInfoSuccessResponse) userInfoResponse).getUserInfo();
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("User info: {}", userInfo == null ? "null" : userInfo.toJSONObject());
        }
        return userInfo;
    }

    /**
     * Verify the OIDC client configuration has been configured correctly.
     * @return true if the provider is not configured
     */
    public boolean checkIfProviderIsNotExist() {
        String provider = OIDCConfigs.getProvider();
        if (provider == null || provider.trim().isEmpty()) {
            LOGGER.warn("OIDC provider is not configured");
            return true;
        }
        return false;
    }

    /**
     * Return the current configure OIDC provider information.
     * @return OIDCProvider
     */
    public OIDCProvider getProviderInfo() {
        if (checkIfProviderIsNotExist()) {
            return null;
        }
        String providerKey = OIDCConfigs.getProvider();
        OIDCProvider provider = new OIDCProvider();
        provider.setName(OIDCConfigs.getNameByKey(providerKey));
        provider.setKey(providerKey);
        return provider;
    }

    /**
     * Get OIDC Token from Authorization Server by exchange the authorization code.
     *
     * @param authorizationCode Authorization Code
     * @param callbackUrl       Callback URL
     * @param nonce             Origin Nonce
     * @return OIDCTokens
     */
    protected OIDCTokens exchangeToken(AuthorizationCode authorizationCode, String callbackUrl, String nonce) {
        OIDCProviderMetadata providerMetadata = getProviderMetadata();
        try {
            TokenRequest request = new TokenRequest(providerMetadata.getTokenEndpointURI(),
                    new ClientSecretBasic(getClientId(), getClientSecret()),
                    new AuthorizationCodeGrant(authorizationCode, new URI(callbackUrl)));
            HTTPResponse response = request.toHTTPRequest().send();
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(response);
            if (tokenResponse instanceof TokenErrorResponse) {
                ErrorObject errorObject = ((TokenErrorResponse) tokenResponse).getErrorObject();
                if (errorObject == null || errorObject.getCode() == null) {
                    throw new IllegalStateException("Token request failed: No error code returned "
                            + "(identity provider might be unreachable)");
                } else {
                    throw new IllegalStateException("Token request failed: " + errorObject.toJSONObject());
                }
            }
            OIDCTokens oidcTokens = ((OIDCTokenResponse) tokenResponse).getOIDCTokens();
            if (isIdTokenSigned()) {
                validateIdToken(providerMetadata.getIssuer(), providerMetadata.getJWKSetURI(), oidcTokens.getIDToken(),
                        nonce);
            }
            return oidcTokens;
        } catch (URISyntaxException | ParseException e) {
            throw new IllegalStateException("Retrieving access token failed", e);
        } catch (IOException e) {
            throw new IllegalStateException("Retrieving access token failed: Identity provider might be unreachable");
        }
    }

    protected UserInfoResponse exchangeUserInfo(URI userInfoEndpointURI, BearerAccessToken accessToken) {
        LOGGER.debug("Retrieving user info from {}", userInfoEndpointURI);
        try {
            UserInfoRequest request = new UserInfoRequest(userInfoEndpointURI, accessToken);
            HTTPResponse response = request.toHTTPRequest().send();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("UserInfo response content: [REDACTED]");
            }
            return UserInfoResponse.parse(response);
        } catch (ParseException e) {
            throw new IllegalStateException("Retrieving user information failed", e);
        } catch (IOException e) {
            throw new IllegalStateException("Retrieving user information failed: Identity provider might be unreachable");
        }
    }

    private void validateIdToken(Issuer issuer, URI jwkSetURI, JWT idToken, String nonce) {
        if (jwkSetURI == null) {
            throw new IllegalStateException("JWK set URI is missing from provider metadata");
        }
        LOGGER.debug("Validating ID token with {} and key set from from {}", getIdTokenSignAlgorithm(), jwkSetURI);
        try {
            IDTokenValidator validator = new IDTokenValidator(issuer, getClientId(), getIdTokenSignAlgorithm(),
                    jwkSetURI.toURL());
            validator.validate(idToken, Nonce.parse(nonce));
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid JWK set URL", e);
        } catch (BadJOSEException e) {
            throw new IllegalStateException("Invalid ID token", e);
        } catch (JOSEException e) {
            throw new IllegalStateException("Validating ID token failed", e);
        }
    }

    protected OIDCProviderMetadata getProviderMetadata() {
        if (config == null) {
            throw new IllegalStateException("OIDC configuration is not initialized");
        }
        LOGGER.debug("Retrieving provider metadata from {}", config.getIssuerUri());
        try {
            return OIDCProviderMetadata.resolve(new Issuer(config.getIssuerUri()));
        } catch (IOException | GeneralException e) {
            if (e instanceof GeneralException) {
                throw new IllegalStateException("Retrieving OpenID Connect provider metadata failed: "
                        + "Issuer URL mismatch");
            } else {
                throw new IllegalStateException("Retrieving OpenID Connect provider metadata failed", e);
            }
        }
    }

    private Scope getScope() {
        return Scope.parse(config.getScope());
    }

    private ClientID getClientId() {
        String clientId = config.getClientId();
        if (clientId == null || clientId.trim().isEmpty()) {
            throw new IllegalStateException("Client ID is not configured");
        }
        return new ClientID(clientId);
    }

    private Secret getClientSecret() {
        String secret = config.getClientSecret();
        return secret == null ? new Secret("") : new Secret(secret);
    }

    private boolean isIdTokenSigned() {
        return config.getIdTokenSignAlgorithm() != null;
    }

    private JWSAlgorithm getIdTokenSignAlgorithm() {
        String algorithmName = config.getIdTokenSignAlgorithm();
        return algorithmName == null ? JWSAlgorithm.RS512 : new JWSAlgorithm(algorithmName);
    }

    private boolean hasEnoughInfo(UserInfo userInfo) {
        return userInfo.getName() != null && !userInfo.getName().trim().isEmpty()
                && userInfo.getPreferredUsername() != null && !userInfo.getPreferredUsername().trim().isEmpty();
    }
}
