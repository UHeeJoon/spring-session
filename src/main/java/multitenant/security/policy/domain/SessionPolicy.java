package multitenant.security.policy.domain;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "session_policy")
public class SessionPolicy {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private String name;

  @Enumerated(EnumType.STRING)
  @Column(name = "condition_type", nullable = false, length = 32)
  private PolicyConditionType conditionType;

  @Column(name = "condition_value", nullable = false, length = 1024)
  private String conditionValue;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 8)
  private PolicyEffect effect;

  @Column(nullable = false)
  private int priority;

  @Column(nullable = false)
  private boolean active = true;

  @OneToMany(mappedBy = "policy", cascade = CascadeType.ALL, orphanRemoval = true,
      fetch = FetchType.LAZY)
  private Set<SessionPolicyScope> scopes = new LinkedHashSet<>();

  public Long getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public PolicyConditionType getConditionType() {
    return conditionType;
  }

  public void setConditionType(PolicyConditionType conditionType) {
    this.conditionType = conditionType;
  }

  public String getConditionValue() {
    return conditionValue;
  }

  public void setConditionValue(String conditionValue) {
    this.conditionValue = conditionValue;
  }

  public PolicyEffect getEffect() {
    return effect;
  }

  public void setEffect(PolicyEffect effect) {
    this.effect = effect;
  }

  public int getPriority() {
    return priority;
  }

  public void setPriority(int priority) {
    this.priority = priority;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public Set<SessionPolicyScope> getScopes() {
    return scopes;
  }

  public void addScope(SessionPolicyScope scope) {
    scopes.add(scope);
    scope.setPolicy(this);
  }

  public void removeScope(SessionPolicyScope scope) {
    scopes.remove(scope);
    scope.setPolicy(null);
  }
}
