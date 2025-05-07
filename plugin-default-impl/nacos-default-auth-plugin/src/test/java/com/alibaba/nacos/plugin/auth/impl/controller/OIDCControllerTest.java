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

import com.alibaba.nacos.common.utils.JacksonUtils;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCClient;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCProvider;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCService;
import com.alibaba.nacos.plugin.auth.impl.oidc.OIDCState;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.Base64Utils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("checkstyle:abbreviationaswordinname")
@ExtendWith(MockitoExtension.class)
class OIDCControllerTest {

    private OIDCClient oidcClient;

    private OIDCService oidcService;

    private OIDCController controller;

    @BeforeEach
    void setUp() {
        oidcClient = mock(OIDCClient.class);
        oidcService = mock(OIDCService.class);
        controller = new OIDCController(oidcClient, oidcService);
    }

    @Test
    void testGetProviderProviderExists() {
        when(oidcClient.getProviderInfo()).thenReturn(mock(OIDCProvider.class));
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);

        assertNotNull(controller.getProvider());
    }

    @Test
    void testGetProviderProviderNotExists() {
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(true);

        assertNull(controller.getProvider());
    }

    @Test
    void testStartAuthenticationProviderNotExists() throws IOException {
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);

        controller.startAuthentication("http://localhost:8848/nacos/#/login", response);

        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    void testStartAuthenticationProviderExists() throws IOException {
        final MockHttpServletResponse response = new MockHttpServletResponse();
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);

        // 模拟 HTTP 请求上下文
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        AuthenticationRequest authRequest = mock(AuthenticationRequest.class);
        when(authRequest.toURI()).thenReturn(URI.create("https://oidc.example.com/auth"));
        when(oidcClient.createAuthenticationRequest(anyString(), anyString())).thenReturn(authRequest);

        controller.startAuthentication("http://localhost:8848/nacos/#/login", response);

        assertTrue(response.isCommitted());
        assertEquals("https://oidc.example.com/auth", response.getRedirectedUrl());

        // 清理上下文（可选）
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void testCallbackStateMismatch() throws Exception {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);

        // 模拟 HTTP 请求上下文
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        State returnedState = new State();
        OIDCState state = new OIDCState("origin", "callbackUrl", "nonce", "originalState");
        when(oidcClient.getUserInfo(any(AuthorizationCode.class), anyString(), anyString()))
                .thenThrow(new IllegalArgumentException());

        controller.callback("code", returnedState.getValue(), response);

        verify(response).sendRedirect(anyString());

        // 清理上下文（可选）
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void testCallbackUserNotFound() throws Exception {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);

        // 构造合法的 OIDCState 实例
        OIDCState state = new OIDCState(
                "http://localhost:8848/nacos/#/login",
                "/v1/auth/oidc/callback",
                "nonce",
                "originalState"
        );

        // 序列化为 JSON 并进行 Base64 编码
        String json = JacksonUtils.toJson(state);
        String encodedState = Base64Utils.encodeToString(json.getBytes(StandardCharsets.UTF_8));

        // 创建 mock 的 State 对象
        State returnedState = mock(State.class);
        when(returnedState.getValue()).thenReturn(encodedState);

        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getPreferredUsername()).thenReturn("user123");
        when(oidcClient.getUserInfo(any(AuthorizationCode.class), anyString(), anyString())).thenReturn(userInfo);
        when(oidcService.getUser("user123")).thenThrow(new AccessException("User not found"));

        controller.callback("code", encodedState, response);

        verify(response).sendRedirect(argThat(url -> url.contains("User not found")));
    }

    @Test
    void testCallbackSuccess() throws Exception {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(oidcClient.checkIfProviderIsNotExist()).thenReturn(false);

        // 构造合法的 OIDCState 实例
        OIDCState state = new OIDCState(
                "http://localhost:8848/nacos/#/login",
                "/v1/auth/oidc/callback",
                "nonce",
                "originalState"
        );

        // 序列化为 JSON 并进行 Base64 编码
        String json = JacksonUtils.toJson(state);
        String encodedState = Base64Utils.encodeToString(json.getBytes(StandardCharsets.UTF_8));

        // 创建 mock 的 State 对象
        State returnedState = mock(State.class);
        when(returnedState.getValue()).thenReturn(encodedState);

        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getPreferredUsername()).thenReturn("user123");
        when(userInfo.getStringListClaim("groups")).thenReturn(Collections.singletonList("group1"));
        when(oidcClient.getUserInfo(any(AuthorizationCode.class), anyString(), anyString())).thenReturn(userInfo);

        NacosUser nacosUser = new NacosUser();
        nacosUser.setToken("token123");
        nacosUser.setUserName("user123");
        nacosUser.setGlobalAdmin(false);
        when(oidcService.getUser("user123")).thenReturn(nacosUser);
        when(oidcService.getTokenTtlInSeconds("token123")).thenReturn(3600L);

        controller.callback("code", encodedState, response);

        verify(response).sendRedirect(argThat(url -> url.contains("token=")));
    }

    @Test
    void testBuildRedirectUriWithPayloadNoHash() throws Exception {
        String result = OIDCController.buildRedirectUriWithPayload(
                "http://localhost:8848/nacos/#/login",
                "token",
                "abc123"
        );
        assertTrue(result.contains("token=abc123"));
    }

    @Test
    void testBuildRedirectUriWithPayloadWithHashAndQuery() throws Exception {
        String result = OIDCController.buildRedirectUriWithPayload(
                "http://example.com#/login?from=auth",
                "msg",
                "error"
        );
        assertTrue(result.contains("#/login?from=auth&msg=error"));
    }
}
