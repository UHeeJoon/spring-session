package multitenant.security.sessionlimit.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

import java.time.Duration;
import java.util.Optional;
import multitenant.security.sessionlimit.domain.TenantSessionLimit;
import multitenant.security.sessionlimit.repository.TenantSessionLimitRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

class TenantSessionLimitServiceTests {

  private TenantSessionLimitRepository repository;
  private TenantSessionLimitService service;

  @BeforeEach
  void setUp() {
    repository = Mockito.mock(TenantSessionLimitRepository.class);
    service = new TenantSessionLimitService(repository);
  }

  @Test
  void resolveForTenantReturnsDefaultsWhenMissing() {
    SessionLimitSettings settings = service.resolveForTenant("unknown");

    assertThat(settings.maxSessions()).isZero();
    assertThat(settings.maxIdle()).isEqualTo(Duration.ofSeconds(1800));
    assertThat(settings.maxDuration()).isZero();
  }

  @Test
  void resolveForTenantUsesPersistedValues() {
    TenantSessionLimit entity = new TenantSessionLimit("tenantA", 2, 600, 3600);
    given(repository.findById("tenantA")).willReturn(Optional.of(entity));

    SessionLimitSettings settings = service.resolveForTenant("tenantA");

    assertThat(settings.maxSessions()).isEqualTo(2);
    assertThat(settings.maxIdle()).isEqualTo(Duration.ofMinutes(10));
    assertThat(settings.maxDuration()).isEqualTo(Duration.ofHours(1));
  }

  @Test
  void resolveForTenantTreatsZeroAsUnlimited() {
    TenantSessionLimit entity = new TenantSessionLimit("tenantZ", 3, 0, 0);
    given(repository.findById("tenantZ")).willReturn(Optional.of(entity));

    SessionLimitSettings settings = service.resolveForTenant("tenantZ");

    assertThat(settings.maxIdle()).isZero();
    assertThat(settings.maxDuration()).isZero();
  }

  @Test
  void upsertPersistsNormalizedValues() {
    ArgumentCaptor<TenantSessionLimit> captor = ArgumentCaptor.forClass(TenantSessionLimit.class);
    given(repository.findById("tenantB")).willReturn(Optional.empty());
    given(repository.save(Mockito.any())).willAnswer(invocation -> invocation.getArgument(0));

    TenantSessionLimit updated = service.upsert("tenantB", -1, -30, 7200);

    verify(repository).save(captor.capture());
    assertThat(captor.getValue().getMaxSessions()).isZero();
    assertThat(captor.getValue().getMaxIdleSeconds()).isZero();
    assertThat(updated.getMaxDurationSeconds()).isEqualTo(7200);
  }

  @Test
  void upsertRejectsBlankTenantId() {
    assertThatThrownBy(() -> service.upsert(" ", 1, 1, 1))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
