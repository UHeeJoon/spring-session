package multitenant.security.policy.admin;

import java.io.Serializable;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.PolicyEffect;

public class PolicyCreationForm implements Serializable {

  private String name;
  private String tenantId;
  private PolicyConditionType conditionType;
  private PolicyEffect effect;
  private Integer priority = 100;
  private boolean active = true;
  private String timeStart;
  private String timeEnd;
  private String timeZoneId;
  private String ipCidrs;
  private String countries;
  private String groupIds;
  private String userIds;
  private String excludedGroupIds;
  private String excludedUserIds;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getTenantId() {
    return tenantId;
  }

  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }

  public PolicyConditionType getConditionType() {
    return conditionType;
  }

  public void setConditionType(PolicyConditionType conditionType) {
    this.conditionType = conditionType;
  }

  public PolicyEffect getEffect() {
    return effect;
  }

  public void setEffect(PolicyEffect effect) {
    this.effect = effect;
  }

  public Integer getPriority() {
    return priority;
  }

  public void setPriority(Integer priority) {
    this.priority = priority;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public String getTimeStart() {
    return timeStart;
  }

  public void setTimeStart(String timeStart) {
    this.timeStart = timeStart;
  }

  public String getTimeEnd() {
    return timeEnd;
  }

  public void setTimeEnd(String timeEnd) {
    this.timeEnd = timeEnd;
  }

  public String getTimeZoneId() {
    return timeZoneId;
  }

  public void setTimeZoneId(String timeZoneId) {
    this.timeZoneId = timeZoneId;
  }

  public String getIpCidrs() {
    return ipCidrs;
  }

  public void setIpCidrs(String ipCidrs) {
    this.ipCidrs = ipCidrs;
  }

  public String getCountries() {
    return countries;
  }

  public void setCountries(String countries) {
    this.countries = countries;
  }

  public String getGroupIds() {
    return groupIds;
  }

  public void setGroupIds(String groupIds) {
    this.groupIds = groupIds;
  }

  public String getUserIds() {
    return userIds;
  }

  public void setUserIds(String userIds) {
    this.userIds = userIds;
  }

  public String getExcludedGroupIds() {
    return excludedGroupIds;
  }

  public void setExcludedGroupIds(String excludedGroupIds) {
    this.excludedGroupIds = excludedGroupIds;
  }

  public String getExcludedUserIds() {
    return excludedUserIds;
  }

  public void setExcludedUserIds(String excludedUserIds) {
    this.excludedUserIds = excludedUserIds;
  }
}
