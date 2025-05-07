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
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.auth.impl.oidc.JwtUtil;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCClient;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCConfig;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCProvider;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCService;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUser;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static com.alibaba.nacos.plugin.auth.impl.controller.OIDCController.buildRedirectUriWithPayload;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@SuppressWarnings("checkstyle:abbreviationaswordinname")
@ExtendWith(MockitoExtension.class)
class OIDCControllerTest {

    @Mock
    private OIDCConfig oidcConfig;

    @Mock
    private OIDCClient oidcClient;

    @Mock
    private OIDCService oidcService;

    @InjectMocks
    private OIDCController oidcController;

    private MockHttpServletResponse response;

    private static final String SECRET_KEY = "your-32-byte-secret-key-here!!!your-32-byte-secret-key-here!!!"
            +
            "your-32-byte-secret-key-here!!!your-32-byte-secret-key-here!!!"
            +
            "your-32-byte-secret-key-here!!!your-32-byte-secret-key-here!!!"
            +
            "your-32-byte-secret-key-here!!!your-32-byte-secret-key-here!!!";

    @BeforeEach
    void setUp() {
        response = new MockHttpServletResponse();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("localhost");
        request.setServerPort(8848);
        request.setContextPath("/nacos");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void testGetProvider() {
        OIDCProvider mockProvider = new OIDCProvider();
        mockProvider.setKey("test-provider");
        mockProvider.setName("Test Provider");

        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);
        when(oidcClient.getProviderInfo()).thenReturn(mockProvider);

        OIDCProvider provider = oidcController.getProvider();

        assertEquals("test-provider", provider.getKey());
        assertEquals("Test Provider", provider.getName());
    }

    @Test
    void testStartAuthentication() throws IOException {
        String origin = "http://localhost:8848/nacos/#/login";

        String callbackUri = ServletUriComponentsBuilder.fromCurrentContextPath().path(OIDCController.CALLBACK_PATH)
                .toUriString();

        AuthenticationRequest authRequest = mock(AuthenticationRequest.class);
        when(authRequest.getState()).thenReturn(new State());
        when(authRequest.getNonce()).thenReturn(new Nonce());
        when(authRequest.toURI()).thenReturn(java.net.URI.create("http://auth-server.com/auth"));
        when(oidcClient.getSecretKey()).thenReturn(SECRET_KEY); // 示例：32字节长
        when(oidcClient.createAuthenticationRequest(callbackUri, origin)).thenReturn(authRequest);
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);

        // 确保 token 非空
        String mockJwtToken = "mocked-jwt-token";

        try (MockedStatic<JwtUtil> mockedJwtUtil = mockStatic(JwtUtil.class)) {
            mockedJwtUtil.when(() -> JwtUtil.generateOidcToken(
                    anyString(), anyString(), anyString(), anyString(), anyString()
            )).thenReturn(mockJwtToken);

            oidcController.startAuthentication(origin, response);
        }

        String expectedRedirectUrl = "http://auth-server.com/auth&token=" + URLEncoder.encode(mockJwtToken, StandardCharsets.UTF_8.name());
        assertEquals(expectedRedirectUrl, response.getRedirectedUrl());
    }

    @Test
    void testCallbackWithValidState() throws Exception {
        final String origin = "http://localhost:8848/nacos/#/login";

        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getPreferredUsername()).thenReturn("nacos");
        when(userInfo.getStringListClaim("groups")).thenReturn(Lists.newArrayList("group1", "group2"));

        NacosUser nacosUser = new NacosUser();
        nacosUser.setUserName("nacos");
        nacosUser.setToken("1234567890");
        nacosUser.setGlobalAdmin(true);

        when(oidcClient.getSecretKey()).thenReturn(SECRET_KEY); // 示例：32字节长
        when(oidcClient.getUserInfo(any(), anyString(), anyString())).thenReturn(userInfo);
        when(oidcService.getUser("nacos")).thenReturn(nacosUser);
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);

        // 生成有效的 JWT Token
        String jwtToken = JwtUtil.generateOidcToken(SECRET_KEY, origin, "callback_uri", "valid_state", "nonce");

        // 执行回调
        String code = "authCode";
        oidcController.callback(code, "valid_state", jwtToken, response);

        ObjectNode result = JacksonUtils.createEmptyJsonNode();
        result.put(Constants.ACCESS_TOKEN, nacosUser.getToken());
        result.put(Constants.TOKEN_TTL, oidcService.getTokenTtlInSeconds(nacosUser.getToken()));
        result.put(Constants.GLOBAL_ADMIN, nacosUser.isGlobalAdmin());
        result.put(Constants.USERNAME, nacosUser.getUserName());

        byte[] resultBytes = Base64.encodeBase64(result.toString().getBytes(StandardCharsets.UTF_8));
        String encodedResult = new String(resultBytes, StandardCharsets.UTF_8);

        String expectedRedirect = buildRedirectUriWithPayload(origin, AuthConstants.OIDC_PARAM_TOKEN, encodedResult);
        assertEquals(expectedRedirect, response.getRedirectedUrl());
    }

    @Test
    void testCallbackWithInvalidToken() throws IOException {
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);
        String origin = "http://localhost:8848/nacos/#/login";

        String invalidJwtToken = "invalid.jwt.token.here";

        oidcController.callback("code", "state", invalidJwtToken, response);

        String expectedRedirect = buildRedirectUriWithPayload(origin, AuthConstants.OIDC_PARAM_MSG, "Invalid token");
        assertEquals(expectedRedirect, response.getRedirectedUrl());
    }

    @Test
    void testCallbackWithMissingUserInfo() throws Exception {
        String origin = "http://localhost:8848/nacos/#/login";
        String validJwtToken = JwtUtil.generateOidcToken(SECRET_KEY, origin, "callback", "state", "nonce");

        when(oidcClient.getSecretKey()).thenReturn(SECRET_KEY); // 示例：32字节长
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);
        try (MockedStatic<JwtUtil> mockedJwtUtil = mockStatic(JwtUtil.class)) {
            mockedJwtUtil.when(() -> JwtUtil.verifyToken(SECRET_KEY, validJwtToken))
                    .thenReturn(true);

            // 同样可以 mock 其他静态方法
            mockedJwtUtil.when(() -> JwtUtil.parseOidcToken(SECRET_KEY, validJwtToken))
                    .thenReturn(ImmutableMap.of(
                            "state", "state",
                            "nonce", "nonce",
                            "callbackUri", "callback",
                            "origin", origin
                    ));

            when(oidcClient.getUserInfo(any(), anyString(), anyString())).thenThrow(new RuntimeException("User info not found"));

            oidcController.callback("code", "state", validJwtToken, response);

            String expectedRedirect = buildRedirectUriWithPayload(origin, AuthConstants.OIDC_PARAM_MSG, "Invalid token");
            assertEquals(expectedRedirect, response.getRedirectedUrl());
        }
    }

}
