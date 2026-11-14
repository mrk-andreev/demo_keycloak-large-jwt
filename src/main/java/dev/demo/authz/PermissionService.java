package dev.demo.authz;

import java.util.Set;

import org.springframework.stereotype.Service;

@Service("permissionService")
public class PermissionService {
    private final CachedPermissions cached;

    PermissionService(CachedPermissions cached) {
        this.cached = cached;
    }

    public boolean has(String subject, String permission) {
        return cached.forSubject(subject).contains(permission);
    }

    public Set<String> all(String subject) {
        return cached.forSubject(subject);
    }
}
