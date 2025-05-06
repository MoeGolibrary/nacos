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

import com.alibaba.nacos.sys.env.EnvUtil;

import java.util.Objects;

/**
 * Open ID Connect Configuration Helper Class.
 *
 * @author Roiocam
 */
@SuppressWarnings("checkstyle:abbreviationaswordinname")
public class OIDCConfigs {

    private static final String PREFIX = "nacos.core.auth.oidc";

    private static final String KEY_FORMAT = ".%s";

    private static final String NAME = PREFIX + ".%s.name";

    private static final String SCOPE = PREFIX + ".%s.scope";

    private static final String CLIENT_ID = PREFIX + ".%s.client-id";

    private static final String CLIENT_SECRET = PREFIX + ".%s.client-secret";

    private static final String ISSUER_URI = PREFIX + ".%s.issuer-uri";

    private static final String ID_TOKEN_SIGN_ALGORITHM = PREFIX + ".%s.id-token-sign-algorithm";

    private static final String SECRET_KEY = PREFIX + ".%s.secret-key";

    public static OIDCConfig getConfiguration(String key) {
        if (key == null) {
            return null;
        }
        OIDCConfig oidcConfig = new OIDCConfig();
        oidcConfig.setName(getValueByKey(NAME, key, false));
        oidcConfig.setScope(getValueByKey(SCOPE, key, false));
        oidcConfig.setClientId(getValueByKey(CLIENT_ID, key, false));
        oidcConfig.setClientSecret(getValueByKey(CLIENT_SECRET, key, false));
        oidcConfig.setIssuerUri(getValueByKey(ISSUER_URI, key, false));
        oidcConfig.setIdTokenSignAlgorithm(getValueByKey(ID_TOKEN_SIGN_ALGORITHM, key, true));
        oidcConfig.setSecretKey(getValueByKey(SECRET_KEY, key, false));
        return oidcConfig;
    }

    public static String getValueByKey(String path, String key, boolean nullable) {
        Objects.requireNonNull(path, "path cannot be null");
        Objects.requireNonNull(key, "key cannot be null");

        String finalKey = String.format(path, key);
        String property = EnvUtil.getProperty(finalKey);

        boolean isRequiredButMissing = !nullable;
        boolean hasEmptyValue = property == null || property.trim().isEmpty();

        if (isRequiredButMissing && hasEmptyValue) {
            throw new IllegalArgumentException("Configuration value cannot be empty");
        }

        return property;
    }

    public static String getProvider() {
        String providerStr = EnvUtil.getProperty(PREFIX, String.class);
        if (providerStr == null || providerStr.trim().isEmpty()) {
            return null;
        }
        String[] split = providerStr.trim().split(",");
        if (split.length != 1) {
            throw new IllegalArgumentException("OIDC provider only support one provider");
        }
        return split[0];
    }

    public static String getNameByKey(String key) {
        return getValueByKey(NAME, key, false);
    }
}
