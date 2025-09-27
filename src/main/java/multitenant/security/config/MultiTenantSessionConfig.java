package multitenant.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Duration;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.session.SessionIdGenerator;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisIndexedHttpSession;

@Configuration
@EnableRedisIndexedHttpSession(redisNamespace = "octatco:sso")
public class MultiTenantSessionConfig {

  @Bean
  public LettuceConnectionFactory lettuceConnectionFactory() {
    return new LettuceConnectionFactory();
  }

  @Bean
  public ObjectMapper objectMapper(Jackson2ObjectMapperBuilder builder) {
    return builder
        .modules(new JavaTimeModule())
        .build();
  }

  @Bean
  public RedisSerializer<Object> springSessionDefaultRedisSerializer(ObjectMapper objectMapper) {
    return RedisSerializer.java();
  }

  @Bean
  public RedisOperations<String, Object> sessionRedisOperations(
      LettuceConnectionFactory lettuceConnectionFactory,
      RedisSerializer<Object> springSessionDefaultRedisSerializer) {

    RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();

    redisTemplate.setConnectionFactory(lettuceConnectionFactory);
    redisTemplate.setDefaultSerializer(springSessionDefaultRedisSerializer);
    redisTemplate.setKeySerializer(RedisSerializer.string());
    redisTemplate.setHashKeySerializer(RedisSerializer.string());

    return redisTemplate;
  }

  @Bean
  public RedisIndexedSessionRepository tenantAwareSessionRepository(
      RedisOperations<String, Object> sessionRedisOperations) {
    RedisIndexedSessionRepository repository =
        new RedisIndexedSessionRepository(sessionRedisOperations);

    // 기본 세션 timeout 은 짧게 유지하고
    repository.setDefaultMaxInactiveInterval(Duration.ofSeconds(1800));

    // UUID 기반으로 세션 키 생성
    repository.setSessionIdGenerator(() -> UUID.randomUUID().toString());
    return repository;
  }

}
