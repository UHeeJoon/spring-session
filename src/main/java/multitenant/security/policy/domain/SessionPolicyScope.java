package multitenant.security.policy.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "session_policy_scope")
public class SessionPolicyScope {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "policy_id", nullable = false)
  private SessionPolicy policy;

  @Enumerated(EnumType.STRING)
  @Column(name = "scope_type", nullable = false, length = 16)
  private PolicyScopeType scopeType;

  @Column(name = "scope_value", nullable = false, length = 256)
  private String scopeValue;

  @Column(name = "excluded", nullable = false)
  private boolean excluded = false;

  public Long getId() {
    return id;
  }

  public SessionPolicy getPolicy() {
    return policy;
  }

  public void setPolicy(SessionPolicy policy) {
    this.policy = policy;
  }

  public PolicyScopeType getScopeType() {
    return scopeType;
  }

  public void setScopeType(PolicyScopeType scopeType) {
    this.scopeType = scopeType;
  }

  public String getScopeValue() {
    return scopeValue;
  }

  public void setScopeValue(String scopeValue) {
    this.scopeValue = scopeValue;
  }

  public boolean isExcluded() {
    return excluded;
  }

  public void setExcluded(boolean excluded) {
    this.excluded = excluded;
  }
}
