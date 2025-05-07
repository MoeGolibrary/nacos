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
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT 工具类，用于生成和解析无状态 OIDC Token.
 *
 * @author xxx
 */
public class JwtUtil {

    /**
     * Token 有效时间（单位：毫秒），默认为 5 分钟.
     */
    private static final long EXPIRATION = 5 * 60 * 1000;

    /**
     * 使用 HS256 算法生成签名 JWT Token.
     *
     * @param secret      密钥
     * @param origin      原始请求来源地址
     * @param callbackUri 回调地址
     * @param state       OIDC 流程中的 state
     * @param nonce       OIDC 流程中的 nonce
     * @return 签名后的 JWT 字符串
     */
    public static String generateOidcToken(String secret, String origin, String callbackUri, String state, String nonce) {
        try {
            // 构建 Claims
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer("nacos-oidc")
                    .subject("oidc-auth-flow")
                    .claim("origin", origin)
                    .claim("callbackUri", callbackUri)
                    .claim("state", state)
                    .claim("nonce", nonce)
                    .expirationTime(new Date(System.currentTimeMillis() + EXPIRATION))
                    .build();

            SignedJWT signedjwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

            // 使用 HMAC-SHA 签名
            JWSSigner signer = new MACSigner(secret.getBytes());
            signedjwt.sign(signer);

            return signedjwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to sign JWT token", e);
        }
    }

    /**
     * 解析并验证 JWT Token 的合法性.
     *
     * @param secret   密钥
     * @param jwtToken 要解析的 JWT 字符串
     * @return 包含原始字段的 Map（如 origin、callbackUri、state、nonce）
     * @throws ParseException 如果解析失败或 Token 格式错误
     * @throws JOSEException  如果签名验证失败
     */
    public static Map<String, Object> parseOidcToken(String secret, String jwtToken) throws ParseException, JOSEException {
        SignedJWT signedjwt = SignedJWT.parse(jwtToken);

        // 验证签名
        JWSVerifier verifier = new MACVerifier(secret.getBytes());
        if (!signedjwt.verify(verifier)) {
            throw new JOSEException("Invalid JWT signature");
        }

        // 获取 Claims
        JWTClaimsSet claims = signedjwt.getJWTClaimsSet();

        // 检查是否过期
        if (claims.getExpirationTime().before(new Date())) {
            throw new JOSEException("JWT token has expired");
        }

        // 提取数据
        Map<String, Object> result = new HashMap<>(4);
        result.put("origin", claims.getStringClaim("origin"));
        result.put("callbackUri", claims.getStringClaim("callbackUri"));
        result.put("state", claims.getStringClaim("state"));
        result.put("nonce", claims.getStringClaim("nonce"));

        return result;
    }

    /**
     * 仅验证 Token 是否合法（不提取内容）.
     *
     * @param secret   密钥
     * @param jwtToken 要验证的 JWT 字符串
     * @return true if valid
     */
    public static boolean verifyToken(String secret, String jwtToken) {
        try {
            SignedJWT signedjwt = SignedJWT.parse(jwtToken);
            JWSVerifier verifier = new MACVerifier(secret.getBytes());
            return signedjwt.verify(verifier) && !isTokenExpired(signedjwt);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 检查 Token 是否已过期.
     */
    private static boolean isTokenExpired(SignedJWT signedjwt) {
        try {
            JWTClaimsSet claims = signedjwt.getJWTClaimsSet();
            return claims.getExpirationTime().before(new Date());
        } catch (ParseException e) {
            return true;
        }
    }
}

