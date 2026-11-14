package dev.demo.authz;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired CacheManager cacheManager;
    @MockitoBean KeycloakAdminClient keycloak;

    @BeforeEach
    void setup() {
        cacheManager.getCache("effectivePermissions").clear();
        when(keycloak.effectivePermissions(anyString()))
                .thenReturn(Set.of("orders:read", "orders:cancel", "trades:read"));
    }

    @Test
    void requiresAuthentication() throws Exception {
        mvc.perform(get("/api/me/permissions"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void frontEndCanQueryFilteredEffectivePermissions() throws Exception {
        mvc.perform(get("/api/me/permissions?prefix=orders:").with(jwt().jwt(j -> j.subject("alice"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(2))
                .andExpect(jsonPath("$.permissions[0]").value("orders:cancel"))
                .andExpect(jsonPath("$.permissions[1]").value("orders:read"));
    }

    @Test
    void batchChecksAndEnforcedBackendPermissionsAgree() throws Exception {
        mvc.perform(post("/api/me/permissions/check")
                        .with(jwt().jwt(j -> j.subject("alice")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"permissions\":[\"orders:cancel\",\"orders:create\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decisions['orders:cancel']").value(true))
                .andExpect(jsonPath("$.decisions['orders:create']").value(false));

        mvc.perform(post("/api/orders/cancel").with(jwt().jwt(j -> j.subject("alice"))))
                .andExpect(status().isOk());
        mvc.perform(post("/api/orders").with(jwt().jwt(j -> j.subject("alice"))))
                .andExpect(status().isForbidden());
    }
}
