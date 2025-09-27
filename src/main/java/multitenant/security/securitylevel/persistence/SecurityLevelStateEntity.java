package multitenant.security.securitylevel.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.time.Instant;
import multitenant.security.securitylevel.SecurityLevel;

@Entity
@Table(name = "security_level_state")
@IdClass(SecurityLevelStateId.class)
public class SecurityLevelStateEntity {

  @Id
  @Column(name = "tenant_id", length = 64)
  private String tenantId;

  @Id
  @Column(name = "user_id", length = 64)
  private String userId;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 16)
  private SecurityLevel level;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(nullable = false)
  private int score;

  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;

  public SecurityLevelStateEntity() {
  }

  public String getTenantId() {
    return tenantId;
  }

  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }

  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public SecurityLevel getLevel() {
    return level;
  }

  public void setLevel(SecurityLevel level) {
    this.level = level;
  }

  public Instant getExpiresAt() {
    return expiresAt;
  }

  public void setExpiresAt(Instant expiresAt) {
    this.expiresAt = expiresAt;
  }

  public int getScore() {
    return score;
  }

  public void setScore(int score) {
    this.score = score;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public void setUpdatedAt(Instant updatedAt) {
    this.updatedAt = updatedAt;
  }
}
