package multitenant.security.securitylevel.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "security_level_event", indexes = {
    @Index(name = "idx_security_event_user", columnList = "tenant_id, user_id, occurred_at")
})
public class SecurityLevelEventEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "tenant_id", nullable = false, length = 64)
  private String tenantId;

  @Column(name = "user_id", nullable = false, length = 64)
  private String userId;

  @Column(name = "action_type", nullable = false, length = 64)
  private String actionType;

  @Column(name = "action_detail", length = 255)
  private String actionDetail;

  @Column(name = "occurred_at", nullable = false)
  private Instant occurredAt;

  public SecurityLevelEventEntity() {
  }

  public Long getId() {
    return id;
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

  public String getActionType() {
    return actionType;
  }

  public void setActionType(String actionType) {
    this.actionType = actionType;
  }

  public String getActionDetail() {
    return actionDetail;
  }

  public void setActionDetail(String actionDetail) {
    this.actionDetail = actionDetail;
  }

  public Instant getOccurredAt() {
    return occurredAt;
  }

  public void setOccurredAt(Instant occurredAt) {
    this.occurredAt = occurredAt;
  }
}
