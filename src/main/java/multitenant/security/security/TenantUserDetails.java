package multitenant.security.security;

import java.util.Collection;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class TenantUserDetails implements UserDetails {

  private final String username;
  private final String password;
  private final String tenantId;
  private final Set<String> groups;
  private final String countryCode;
  private final Set<SimpleGrantedAuthority> authorities;

  public TenantUserDetails(String username, String password, String tenantId, Set<String> groups,
      String countryCode, Set<String> roles) {
    this.username = username;
    this.password = password;
    this.tenantId = tenantId;
    this.groups = groups;
    this.countryCode = countryCode;
    this.authorities = roles.stream()
        .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
        .map(SimpleGrantedAuthority::new)
        .collect(java.util.stream.Collectors.toSet());
  }

  public String getTenantId() {
    return tenantId;
  }

  public Set<String> getGroups() {
    return groups;
  }

  public String getCountryCode() {
    return countryCode;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
