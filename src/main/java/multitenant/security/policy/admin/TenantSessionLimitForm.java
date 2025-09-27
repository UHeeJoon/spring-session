package multitenant.security.policy.admin;

public class TenantSessionLimitForm {

  private String tenantId;
  private Integer maxSessions;
  private Integer maxIdleSeconds;
  private Integer maxDurationSeconds;

  public String getTenantId() {
    return tenantId;
  }

  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }

  public Integer getMaxSessions() {
    return maxSessions;
  }

  public void setMaxSessions(Integer maxSessions) {
    this.maxSessions = maxSessions;
  }

  public Integer getMaxIdleSeconds() {
    return maxIdleSeconds;
  }

  public void setMaxIdleSeconds(Integer maxIdleSeconds) {
    this.maxIdleSeconds = maxIdleSeconds;
  }

  public Integer getMaxDurationSeconds() {
    return maxDurationSeconds;
  }

  public void setMaxDurationSeconds(Integer maxDurationSeconds) {
    this.maxDurationSeconds = maxDurationSeconds;
  }
}
