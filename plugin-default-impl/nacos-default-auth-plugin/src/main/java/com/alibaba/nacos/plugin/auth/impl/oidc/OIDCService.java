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

import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.auth.impl.persistence.RoleInfo;
import com.alibaba.nacos.plugin.auth.impl.persistence.User;
import com.alibaba.nacos.plugin.auth.impl.roles.NacosRoleServiceImpl;
import com.alibaba.nacos.plugin.auth.impl.token.TokenManagerDelegate;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUser;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUserDetails;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.ArrayList;
import java.util.stream.Collectors;

/**
 * Open ID Connect User and Token Service.
 *
 * @author Roiocam
 */
@SuppressWarnings("checkstyle:abbreviationaswordinname")
@Service
public class OIDCService {

    private static final String USER_NOT_FOUND = "user not found";

    private final NacosUserDetailsServiceImpl userDetailsService;

    private final NacosRoleServiceImpl roleService;

    private final TokenManagerDelegate jwtTokenManager;

    @Autowired
    public OIDCService(NacosUserDetailsServiceImpl userDetailsService, NacosRoleServiceImpl roleService, TokenManagerDelegate jwtTokenManager) {
        this.userDetailsService = userDetailsService;
        this.roleService = roleService;
        this.jwtTokenManager = jwtTokenManager;
    }

    private NacosUser generateUserFromUsername(String username) throws AccessException {
        String token = jwtTokenManager.createToken(username);
        Authentication authentication = jwtTokenManager.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return new NacosUser(username, token);
    }

    private NacosUser getUserFromNacos(String username) throws AccessException {
        if (StringUtils.isBlank(username)) {
            throw new AccessException(USER_NOT_FOUND);
        }
        UserDetails nacosUserDetails = userDetailsService.loadUserByUsername(username);
        if (!(nacosUserDetails instanceof NacosUserDetails)) {
            throw new AccessException(USER_NOT_FOUND);
        }
        return generateUserFromUsername(nacosUserDetails.getUsername());
    }

    public NacosUser getUser(String username) throws AccessException {
        try {
            return getUserFromNacos(username);
        } catch (AccessException | UsernameNotFoundException e) {
            if (Loggers.AUTH.isInfoEnabled()) {
                Loggers.AUTH.info("[OIDC] Try login via LDAP prefix, user: {}", username, e);
            }
        }

        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(AuthConstants.LDAP_PREFIX + username);
            return generateUserFromUsername(userDetails.getUsername());
        } catch (UsernameNotFoundException e) {
            if (Loggers.AUTH.isInfoEnabled()) {
                Loggers.AUTH.info("[OIDC] Try login via OIDC prefix, user: {}", username, e);
            }
        }

        String oidcUsername = AuthConstants.OIDC_PREFIX + username;
        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(oidcUsername);
        } catch (UsernameNotFoundException ignored) {
            // 注释说明：创建无密码的 OIDC 用户是预期行为
            userDetailsService.createUser(oidcUsername, "");
            User user = new User();
            user.setUsername(oidcUsername);
            user.setPassword("");
            userDetails = new NacosUserDetails(user);
        } catch (Exception e) {
            Loggers.AUTH.error("[OIDC-LOGIN] failed", e);
            throw new AccessException(USER_NOT_FOUND);
        }

        return generateUserFromUsername(userDetails.getUsername());
    }

    public long getTokenTtlInSeconds(String token) {
        try {
            return jwtTokenManager.getTokenTtlInSeconds(token);
        } catch (AccessException e) {
            Loggers.AUTH.error("[TOKEN-TTL] Failed to get token TTL", e);
            return 18000;
        }
    }

    /**
     * Sync roles from OIDC to Nacos.
     *
     * @param username username
     * @param roles    roles
     */
    public void syncRoles(String username, List<String> roles) {
        List<String> oldRoles = roleService.getRoles(username).stream()
                .map(RoleInfo::getRole)
                .collect(Collectors.toList());

        List<String> mutableRoles = new ArrayList<>(roles);

        // delete old roles
        for (String oldRole : oldRoles) {
            if (!oldRole.startsWith(AuthConstants.OIDC_ROLE_PREFIX)) {
                continue;
            }
            if (mutableRoles.contains(oldRole)) {
                mutableRoles.remove(oldRole);
                continue;
            }
            roleService.deleteRole(oldRole, username);
        }

        // add new roles
        for (String role : mutableRoles) {
            if (role.startsWith(AuthConstants.OIDC_ROLE_PREFIX)) {
                roleService.addRole(role, username);
            }
        }
    }
}
