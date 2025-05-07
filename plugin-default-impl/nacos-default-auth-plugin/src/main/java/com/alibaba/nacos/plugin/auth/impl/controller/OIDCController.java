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
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
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

    static String buildRedirectUriWithPayload(String origin, String resultCode, String result) throws UnsupportedEncodingException {
        origin = URLDecoder.decode(origin, StandardCharsets.UTF_8.name());
        // split the origin URL into base URL and hash route
        int hashIndex = origin.indexOf(AuthConstants.HASH_ROUTE);
        String baseUrl = hashIndex != -1 ? origin.substring(0, hashIndex) : origin;
        String hashRoute = hashIndex != -1 ? origin.substring(hashIndex) : "";

        // build redirect url with hash route and token
        UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(baseUrl);
        if (!hashRoute.isEmpty()) {
            StringBuilder sb = new StringBuilder(hashRoute);
            if (hashRoute.contains(AuthConstants.QUERY_PREFIX)) {
                sb.append(AuthConstants.QUERY_PARAM_SEPARATOR);
            } else {
                sb.append(AuthConstants.QUERY_PREFIX);
            }
            hashRoute = sb.append(resultCode).append(AuthConstants.QUERY_PARAM_EQUAL).append(result).toString();
        }
        return URLDecoder.decode(redirectUriBuilder.build().toUriString() + hashRoute, StandardCharsets.UTF_8.name());
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
     * @throws IOException IOException
     */
    @GetMapping("/start")
    public void startAuthentication(@RequestParam("origin") String origin, HttpServletResponse response) throws IOException {
        if (oidcClient.checkIfProviderIsNotExist()) {
            return;
        }

        URI originUri = URI.create(origin);
        String callbackUri = ServletUriComponentsBuilder.fromCurrentContextPath().scheme(originUri.getScheme()).path(CALLBACK_PATH)
                .toUriString();

        AuthenticationRequest authRequest = oidcClient.createAuthenticationRequest(callbackUri, origin);

        response.sendRedirect(authRequest.toURI().toString());
    }

    /**
     * Authorization server callback this interface, process the authorization code and exchange token.
     *
     * @param code          Authorization Code
     * @param returnedState State returned by the authorization server
     * @param response      HttpServletResponse
     * @throws IOException IOException
     */
    @GetMapping("/callback")
    public void callback(@RequestParam("code") String code,
                         @RequestParam("state") String returnedState,
                         HttpServletResponse response) throws IOException {

        if (oidcClient.checkIfProviderIsNotExist()) {
            return;
        }
        try {
            // 解析state
            OIDCState state = OIDCState.fromState(State.parse(returnedState));
            String callbackUri = state.getCallbackUrl();
            String nonce = state.getNonce();
            String origin = state.getOrigin();
            String originalState = state.getState();

            if (!originalState.equals(returnedState)) {
                String uriString = buildRedirectUriWithPayload(origin, AuthConstants.OIDC_PARAM_MSG, "Invalid state");
                response.sendRedirect(uriString);
                return;
            }

            UserInfo userInfo = oidcClient.getUserInfo(new AuthorizationCode(code), callbackUri, nonce);

            List<String> groups = userInfo.getStringListClaim("groups")
                    .stream()
                    .map(s -> AuthConstants.OIDC_ROLE_PREFIX + s.toUpperCase())
                    .collect(Collectors.toList());

            Loggers.AUTH.warn("try login with LDAP, user: {}, groups: {}, email: {}, profile: {}",
                    userInfo, groups, userInfo.getClaim("email"), userInfo.getClaim("profile"));
            String preferredUsername = userInfo.getPreferredUsername();
            NacosUser nacosUser;
            try {
                nacosUser = oidcService.getUser(preferredUsername);
            } catch (AccessException e) {
                String uriString = buildRedirectUriWithPayload(origin, AuthConstants.OIDC_PARAM_MSG, "User not found");
                response.sendRedirect(uriString);
                return;
            }

            oidcService.syncRoles(nacosUser.getUserName(), groups);

            ObjectNode result = JacksonUtils.createEmptyJsonNode();
            result.put(Constants.ACCESS_TOKEN, nacosUser.getToken());
            result.put(Constants.TOKEN_TTL, oidcService.getTokenTtlInSeconds(nacosUser.getToken()));
            result.put(Constants.GLOBAL_ADMIN, nacosUser.isGlobalAdmin());
            result.put(Constants.USERNAME, nacosUser.getUserName());

            byte[] resultCodedBytes = Base64.encodeBase64(result.toString().getBytes(StandardCharsets.UTF_8));
            String encodedResult = new String(resultCodedBytes, StandardCharsets.UTF_8);

            String uriString = buildRedirectUriWithPayload(origin, AuthConstants.OIDC_PARAM_TOKEN, encodedResult);
            response.sendRedirect(uriString);

        } catch (Exception e) {
            String missingOrigin = ServletUriComponentsBuilder.fromCurrentContextPath().path(AuthConstants.LOGIN_PAGE)
                    .toUriString();
            String uriString = buildRedirectUriWithPayload(missingOrigin, AuthConstants.OIDC_PARAM_MSG, "Invalid token");
            response.sendRedirect(uriString);
        }
    }

}
