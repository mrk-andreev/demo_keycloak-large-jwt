package dev.demo.authz;

import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PermissionServiceTest {
    @Test
    void checksOnlyResolvedPermissionsForSubject() {
        CachedPermissions cached = mock(CachedPermissions.class);
        when(cached.forSubject("keycloak-sub-123"))
                .thenReturn(Set.of("orders:read", "orders:cancel"));
        PermissionService permissions = new PermissionService(cached);

        assertTrue(permissions.has("keycloak-sub-123", "orders:read"));
        assertTrue(permissions.has("keycloak-sub-123", "orders:cancel"));
        assertFalse(permissions.has("keycloak-sub-123", "orders:create"));
    }
}
