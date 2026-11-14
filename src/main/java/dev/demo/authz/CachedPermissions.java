package dev.demo.authz;

import java.util.Set;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
public class CachedPermissions {
    private final KeycloakAdminClient keycloak;

    CachedPermissions(KeycloakAdminClient keycloak) {
        this.keycloak = keycloak;
    }

    @Cacheable(cacheNames = "effectivePermissions", sync = true)
    public Set<String> forSubject(String subject) {
        return keycloak.effectivePermissions(subject);
    }
}
