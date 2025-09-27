package multitenant.security.sessionlimit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "tenant_session_limit")
public class TenantSessionLimit {

  @Id
  @Column(name = "tenant_id", nullable = false, length = 64)
  private String tenantId;

  @Column(name = "max_sessions", nullable = false)
  private int maxSessions;

  @Column(name = "max_idle_seconds", nullable = false)
  private int maxIdleSeconds;

  @Column(name = "max_duration_seconds", nullable = false)
  private int maxDurationSeconds;

  protected TenantSessionLimit() {
  }

  public TenantSessionLimit(String tenantId, int maxSessions, int maxIdleSeconds,
      int maxDurationSeconds) {
    this.tenantId = tenantId;
    this.maxSessions = maxSessions;
    this.maxIdleSeconds = maxIdleSeconds;
    this.maxDurationSeconds = maxDurationSeconds;
  }

  public String getTenantId() {
    return tenantId;
  }

  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }

  public int getMaxSessions() {
    return maxSessions;
  }

  public void setMaxSessions(int maxSessions) {
    this.maxSessions = maxSessions;
  }

  public int getMaxIdleSeconds() {
    return maxIdleSeconds;
  }

  public void setMaxIdleSeconds(int maxIdleSeconds) {
    this.maxIdleSeconds = maxIdleSeconds;
  }

  public int getMaxDurationSeconds() {
    return maxDurationSeconds;
  }

  public void setMaxDurationSeconds(int maxDurationSeconds) {
    this.maxDurationSeconds = maxDurationSeconds;
  }
}
