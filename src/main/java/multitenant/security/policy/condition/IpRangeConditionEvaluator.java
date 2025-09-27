package multitenant.security.policy.condition;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.SessionPolicy;
import multitenant.security.policy.service.PolicyEvaluationContext;
import org.springframework.stereotype.Component;

@Component
class IpRangeConditionEvaluator implements PolicyConditionEvaluator {

  private final ObjectMapper objectMapper;

  IpRangeConditionEvaluator(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public boolean supports(PolicyConditionType conditionType) {
    return conditionType == PolicyConditionType.IP_RANGE;
  }

  @Override
  public boolean matches(SessionPolicy policy, PolicyEvaluationContext context) {
    if (context.clientIp() == null || context.clientIp().isBlank()) {
      return false;
    }
    try {
      IpRangeCondition condition =
          objectMapper.readValue(policy.getConditionValue(), IpRangeCondition.class);
      List<String> cidrList = condition.cidr() == null ? Collections.emptyList() : condition.cidr();
      if (cidrList.isEmpty()) {
        return false;
      }
      long ipValue = toNumeric(context.clientIp());
      for (String cidr : cidrList) {
        if (cidr == null || cidr.isBlank()) {
          continue;
        }
        CidrRange range = parseCidr(cidr.trim());
        if (range == null) {
          continue;
        }
        if (range.contains(ipValue)) {
          return true;
        }
      }
      return false;
    } catch (Exception ex) {
      return false;
    }
  }

  private CidrRange parseCidr(String cidr) {
    String[] parts = cidr.split("/");
    if (parts.length != 2) {
      return null;
    }
    try {
      long base = toNumeric(parts[0]);
      int prefix = Integer.parseInt(parts[1]);
      if (prefix < 0 || prefix > 32) {
        return null;
      }
      long mask = prefix == 0 ? 0 : ~((1L << (32 - prefix)) - 1) & 0xFFFFFFFFL;
      return new CidrRange(base & mask, mask);
    } catch (Exception ex) {
      return null;
    }
  }

  private long toNumeric(String ip) throws UnknownHostException {
    InetAddress address = InetAddress.getByName(ip);
    byte[] bytes = address.getAddress();
    if (bytes.length != 4) {
      throw new UnknownHostException("Only IPv4 addresses are supported");
    }
    long result = 0;
    for (byte b : bytes) {
      result = (result << 8) | (b & 0xFF);
    }
    return result & 0xFFFFFFFFL;
  }

  private record IpRangeCondition(List<String> cidr) {
  }

  private record CidrRange(long network, long mask) {
    boolean contains(long ip) {
      return (ip & mask) == network;
    }
  }
}
