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

package com.alibaba.nacos.plugin.auth.impl.controller;

import com.alibaba.nacos.api.common.Constants;
import com.alibaba.nacos.common.codec.Base64;
import com.alibaba.nacos.common.utils.JacksonUtils;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCClient;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCProvider;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCService;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCState;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUser;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Open ID Connect Endpoint.
 *
 * @author Roiocam
 */
@SuppressWarnings("checkstyle:abbreviationaswordinname")
@RestController
@RequestMapping(OIDCController.PATH)
public class OIDCController {

    public static final String PATH = "/v1/auth/oidc";

    public static final String CALLBACK_PATH = PATH + "/callback";

    private final OIDCClient oidcClient;

    private final OIDCService oidcService;

    @Autowired
    public OIDCController(OIDCClient oidcClient, OIDCService oidcService) {
        this.oidcClient = oidcClient;
        this.oidcService = oidcService;
    }

    private static String buildRedirectUriWithPayload(String origin, String resultCode, String result) throws UnsupportedEncodingException {
        if (origin == null || origin.isEmpty()) {
            throw new IllegalArgumentException("Origin URL cannot be null or empty");
        }
        UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(origin);
        int hashIndex = origin.indexOf(AuthConstants.HASH_ROUTE);

        String baseUrl = hashIndex != -1 ? origin.substring(0, hashIndex) : origin;
        String hashRoute = hashIndex != -1 ? origin.substring(hashIndex) : "";

        UriComponentsBuilder baseBuilder = UriComponentsBuilder.fromUriString(baseUrl);

        // Append result code and value after hash
        StringBuilder hashBuilder = new StringBuilder(hashRoute);
        if (hashRoute.contains(AuthConstants.QUERY_PREFIX)) {
            hashBuilder.append(AuthConstants.QUERY_PARAM_SEPARATOR);
        } else {
            hashBuilder.append(AuthConstants.QUERY_PREFIX);
        }
        hashBuilder.append(resultCode).append(AuthConstants.QUERY_PARAM_EQUAL).append(UriUtils.encode(result, StandardCharsets.UTF_8));

        String fullUrl = baseBuilder.build().toUriString() + hashBuilder.toString();
        return URLDecoder.decode(fullUrl, StandardCharsets.UTF_8.name());
    }

    /**
     * Get current OIDC provider.
     */
    @GetMapping("/provider")
    public OIDCProvider getProvider() {
        if (oidcClient.checkIfProviderIsNotExist()) {
            return null;
        }
        return oidcClient.getProviderInfo();
    }

    /**
     * Start Open ID Connect Authentication Flow.
     *
     * @param response HttpServletResponse
     * @param session  HttpSession
     * @throws IOException IOException
     */
    @GetMapping("/start")
    public void startAuthentication(@RequestParam("origin") String origin, HttpServletResponse response, HttpSession session) throws IOException {
        if (oidcClient.checkIfProviderIsNotExist()) {
            return;
        }

        URI originUri = URI.create(origin);
        String callbackUri = ServletUriComponentsBuilder.fromCurrentContextPath().scheme(originUri.getScheme()).path(CALLBACK_PATH).toUriString();

        Loggers.AUTH.info("OIDC callback uri: {}", callbackUri);

        AuthenticationRequest authRequest = oidcClient.createAuthenticationRequest(callbackUri, origin);

        Loggers.AUTH.debug("OIDC auth request: {}", authRequest);

        session.setAttribute(AuthConstants.OIDC_STATE, authRequest.getState().getValue());
        session.setAttribute(AuthConstants.OIDC_NONCE, authRequest.getNonce().getValue());

        // Redirect to Authentication endpoint
        response.sendRedirect(authRequest.toURI().toString());
    }

    /**
     * Authorization server callback this interface, process the authorization code and exchange token.
     *
     * @param code          Authorization Code
     * @param returnedState State returned by the authorization server
     * @param response      HttpServletResponse
     * @param session       HttpSession
     * @throws IOException IOException
     */
    @GetMapping("/callback")
    public void callback(@RequestParam("code") String code, @RequestParam("state") String returnedState,
                         HttpServletResponse response, HttpSession session)
            throws IOException {
        if (oidcClient.checkIfProviderIsNotExist()) {
            Loggers.AUTH.warn("[OIDC] Provider is not configured, ignoring callback.");
            return;
        }

        Loggers.AUTH.info("[OIDC][Session:{}] Callback received with code={} state={}", session.getId(), code, returnedState);

        String originalState = (String) session.getAttribute(AuthConstants.OIDC_STATE);
        if (originalState == null) {
            Loggers.AUTH.warn("[OIDC][Session:{}] Session expired or missing OIDC_STATE", session.getId());
            handleSessionExpired(response, session);
            return;
        }

        if (!originalState.equals(returnedState)) {
            Loggers.AUTH.warn("[OIDC][Session:{}] Invalid state provided, expected={}, actual={}", session.getId(), originalState, returnedState);
            handleInvalidState(response, session, returnedState);
            return;
        }

        String callbackUri = ServletUriComponentsBuilder.fromCurrentContextPath().path(CALLBACK_PATH).toUriString();
        UserInfo userInfo = oidcClient.getUserInfo(new AuthorizationCode(code), callbackUri, (String) session.getAttribute(AuthConstants.OIDC_NONCE));
        session.removeAttribute(AuthConstants.OIDC_STATE);
        session.removeAttribute(AuthConstants.OIDC_NONCE);

        List<String> groups = getGroupsFromUserInfo(userInfo);
        logUserInfo(userInfo, groups);

        NacosUser nacosUser = processUserInfo(userInfo, session, response);
        if (nacosUser == null) {
            Loggers.AUTH.warn("[OIDC][Session:{}] Failed to process user info for login", session.getId());
            return;
        }

        Loggers.AUTH.info("[OIDC][User:{}] Syncing roles: {}", nacosUser.getUserName(), groups);
        oidcService.syncRoles(nacosUser.getUserName(), groups);

        setSessionAttributes(session, nacosUser);

        sendAuthHeaderAndRedirect(response, nacosUser, userInfo, session);
    }

    private void handleSessionExpired(HttpServletResponse response, HttpSession session) throws IOException {
        session.removeAttribute(AuthConstants.OIDC_STATE);
        session.removeAttribute(AuthConstants.OIDC_NONCE);
        String missingOrigin = ServletUriComponentsBuilder.fromCurrentContextPath().path(AuthConstants.LOGIN_PAGE).toUriString();
        String uriString = buildRedirectUriWithPayload(missingOrigin, AuthConstants.OIDC_PARAM_MSG, "Session expired");
        response.sendRedirect(uriString);
    }

    private void handleInvalidState(HttpServletResponse response, HttpSession session, String returnedState) throws IOException {
        session.removeAttribute(AuthConstants.OIDC_STATE);
        session.removeAttribute(AuthConstants.OIDC_NONCE);

        Loggers.AUTH.warn("[OIDC][Session:{}] Invalid state detected: {}", session.getId(), returnedState);

        String json = Base64URL.from(returnedState).decodeToString();
        try {
            OIDCState state = JacksonUtils.toObj(json, OIDCState.class);
            String uriString = buildRedirectUriWithPayload(state.getOrigin(), AuthConstants.OIDC_PARAM_MSG, "Invalid state");
            response.sendRedirect(uriString);
        } catch (Exception e) {
            Loggers.AUTH.error("[OIDC] Failed to parse returned state: {}", returnedState, e);
            String missingOrigin = ServletUriComponentsBuilder.fromCurrentContextPath().path(AuthConstants.LOGIN_PAGE).toUriString();
            String uriString = buildRedirectUriWithPayload(missingOrigin, AuthConstants.OIDC_PARAM_MSG, "Invalid state format");
            response.sendRedirect(uriString);
        }
    }

    private List<String> getGroupsFromUserInfo(UserInfo userInfo) {
        return userInfo.getStringListClaim("groups").stream()
                .filter(Objects::nonNull).map(s -> AuthConstants.OIDC_ROLE_PREFIX + s.toUpperCase()).collect(Collectors.toList());
    }

    private void logUserInfo(UserInfo userInfo, List<String> groups) {
        Loggers.AUTH.debug("try login with OIDC, user: {}, groups: {}, email: {}, profile: {}", userInfo.getSubject(),
                groups, userInfo.getClaim("email"), userInfo.getClaim("profile"));
    }

    private NacosUser processUserInfo(UserInfo userInfo, HttpSession session, HttpServletResponse response) throws UnsupportedEncodingException {
        String preferredUsername = userInfo.getPreferredUsername();
        try {
            return oidcService.getUser(preferredUsername);
        } catch (AccessException e) {
            String json = Base64URL.from((String) session.getAttribute(AuthConstants.OIDC_STATE)).decodeToString();
            OIDCState state = JacksonUtils.toObj(json, OIDCState.class);
            String uriString = buildRedirectUriWithPayload(state.getOrigin(), AuthConstants.OIDC_PARAM_MSG, "User not found");
            try {
                response.sendRedirect(uriString);
            } catch (IOException ex) {
                Loggers.AUTH.error("Failed to redirect after user not found", ex);
            }
            return null;
        }
    }

    private void setSessionAttributes(HttpSession session, NacosUser nacosUser) {
        session.setAttribute(AuthConstants.NACOS_USER_KEY, nacosUser);
        session.setAttribute(com.alibaba.nacos.plugin.auth.constant.Constants.Identity.IDENTITY_ID, nacosUser.getUserName());
    }

    private void sendAuthHeaderAndRedirect(HttpServletResponse response, NacosUser nacosUser, UserInfo userInfo,
                                           HttpSession session) throws IOException {
        if (session.getAttribute(AuthConstants.OIDC_STATE) == null) {
            Loggers.AUTH.warn("[OIDC][Session:{}] Cannot redirect, OIDC_STATE is missing", session.getId());
            return;
        }

        final String json = Base64URL.from((String) session.getAttribute(AuthConstants.OIDC_STATE)).decodeToString();
        final OIDCState state = JacksonUtils.toObj(json, OIDCState.class);

        Loggers.AUTH.info("[OIDC][User:{}] Sending auth header and redirecting to origin: {}", nacosUser.getUserName(), state.getOrigin());

        response.addHeader(AuthConstants.AUTHORIZATION_HEADER, AuthConstants.TOKEN_PREFIX + nacosUser.getToken());

        ObjectNode result = JacksonUtils.createEmptyJsonNode();
        result.put(Constants.ACCESS_TOKEN, nacosUser.getToken());
        result.put(Constants.TOKEN_TTL, oidcService.getTokenTtlInSeconds(nacosUser.getToken()));
        result.put(Constants.GLOBAL_ADMIN, nacosUser.isGlobalAdmin());
        result.put(Constants.USERNAME, nacosUser.getUserName());

        byte[] resultCodedBytes = Base64.encodeBase64(result.toString().getBytes(StandardCharsets.UTF_8));
        String encodedResult = UriUtils.encode(new String(resultCodedBytes, StandardCharsets.UTF_8), StandardCharsets.UTF_8);

        String uriString = buildRedirectUriWithPayload(state.getOrigin(), AuthConstants.OIDC_PARAM_TOKEN, encodedResult);
        try {
            response.sendRedirect(uriString);
        } catch (IOException e) {
            Loggers.AUTH.error("[OIDC] Redirect failed for user [{}]", nacosUser.getUserName(), e);
        }
    }
}

