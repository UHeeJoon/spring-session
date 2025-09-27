# 다중 테넌트 세션 보안 예제

## 소개
이 프로젝트는 다중 테넌트 SaaS 환경에서 세션 기반 접근 제어와 리스크 기반 인증 강화를 실험하기 위한 Spring Boot 3.5.6 애플리케이션입니다. Redis 인덱스 세션과 MySQL 정책 저장소를 사용해 테넌트별 세션 정책을 평가하고, 사용자 행동 이벤트를 기반으로 보안 등급을 계산합니다. WebAuthn 및 기존 폼 로그인을 함께 제공하며, 정책 작성과 테스트를 위한 관리 UI를 포함합니다.

## 기술 스택
- Java 24, Spring Boot 3.5.6
- Spring Security + WebAuthn, Spring Session(Data Redis), Spring Data JPA
- MySQL 8.0 및 Redis
- Thymeleaf 기반 관리 콘솔

## 주요 디렉터리
```
src/main/java/multitenant/security/
├── config/              # Spring Security, Redis 세션, RestClient 설정
├── policy/              # 세션 정책 도메인/서비스/관리 UI
├── security/            # 로그인 사용자 모델과 후처리 핸들러
├── securitylevel/       # 사용자 보안 레벨 계산 및 저장
├── web/                 # 홈/로그인/관리 컨트롤러
└── TestController.java  # 세션 모킹 REST 엔드포인트

src/main/resources/
├── application.yml      # 로컬 환경 기본 설정
├── data.sql             # 초기 세션 정책 시드 데이터
└── templates/           # 대시보드 & 정책 관리 화면

src/test/java/multitenant/security/
├── policy/              # 정책 서비스 & 관리자 테스트
├── securitylevel/       # 보안 레벨 서비스 테스트
└── SecurityApplicationTests.java
```

## 핵심 구성요소
- `SessionPolicy` / `SessionPolicyScope`: MySQL 기반 정책 엔티티와 테넌트·그룹·사용자 범위를 정의합니다.
- `SessionPolicyService`: 정책을 테넌트별로 조회하고 조건 평가(`TIME_WINDOW`, `IP_RANGE`, `LOCATION`)를 수행합니다.
- `SessionPolicyFilter`: 모든 인증된 요청마다 정책 및 보안 레벨을 확인하고, 세션에 `sessionPolicy:lastAppliedId`, `sessionPolicy:lastEffect`, `sessionSecurity:level`을 기록합니다.
- `SecurityLevelService`: 사용자 행동 이벤트를 저장하고 `security.level.policies` 설정에 따라 LOW/MEDIUM/HIGH 등급과 TTL을 계산합니다.
- `PolicyAdminController`: 정책 CRUD, 평가 시뮬레이션, 보안 이벤트 등록을 제공하는 Thymeleaf 기반 관리자 화면입니다.
- `TenantSessionLimitService`: 테넌트별 최대 세션 수, 세션 유휴 시간, 세션 최대 유지 시간을 저장/적용합니다.
- 세션 정책은 그룹/사용자 포함 대상과 더불어 제외 대상을 설정해 특정 조건에서 정책을 무시하도록 구성할 수 있습니다.
- `SecurityConfig`: WebAuthn + 폼 로그인을 구성하고, `alice`, `bob`, `admin` 기본 계정을 제공합니다.

## 초기 데이터
`src/main/resources/data.sql`은 프로젝트 기동 시 아래와 같은 샘플 정책을 자동으로 적재합니다.
- tenant1: 업무 시간 허용/야간 차단, 공인 IP 범위 허용, 특정 국가 차단
- tenant2: 업무 시간 허용, 특정 사용자 + 국가 조합 차단

`tenant_session_limit` 테이블은 테넌트별 세션 정책을 아래와 같이 초기화합니다.
- tenant1: 최대 동시 세션 3개, 유휴 제한 1200초, 최대 유지 7200초
- tenant2: 최대 동시 세션 2개, 유휴 제한 900초, 최대 유지 3600초

## 실행 전 준비
1. JDK 24 이상과 Docker(Compose v2)를 설치합니다.
2. MySQL과 Redis가 이미 실행 중이면 포트를 맞춰 사용하거나 `docker-compose.yml`을 수정합니다.
3. 프로젝트 루트에서 아래 명령으로 의존 서비스를 기동합니다.

```bash
docker compose up -d
```

도커 컨테이너는 각각 `./data/mysql`, `./data/redis` 볼륨을 사용하며 개발용 데이터이므로 자유롭게 초기화할 수 있습니다.

## 애플리케이션 실행
```bash
./gradlew bootRun
```
기본 포트는 `8080`입니다. 브라우저에서 `http://localhost:8080/login`으로 접속하고 아래 계정 중 하나로 로그인합니다.
- `alice` / `password` (tenant1, engineering, KR)
- `bob` / `password` (tenant2, sales, US)
- `admin` / `admin123` (tenant1, engineering/security, KR)

로그인 후 홈 대시보드에서 세션에 기록된 속성 및 최신 정책 적용 내역을 확인할 수 있고, "정책 관리 화면" 버튼을 통해 `/admin/policies`로 이동합니다.

## 정책 관리 & 테스트
- "정책 생성" 폼에서 정책 이름, 테넌트, 조건 유형(`TIME_WINDOW`, `IP_RANGE`, `LOCATION`), 효과(ALLOW/DENY), 우선순위, 범위를 지정할 수 있습니다.
- "정책 평가" 섹션은 임의의 세션 컨텍스트/요청 시각을 입력해 `SessionPolicyService` 평가 결과(허용/거부, 적용된 정책 ID)를 확인합니다.
- "세션 컨텍스트 시뮬레이션" 버튼은 현재 브라우저 세션에 입력값을 저장해 이후 요청에서 `SessionPolicyFilter`가 동일한 값을 활용하도록 합니다.
- "보안 레벨 이벤트 기록" 폼에서 `LOGIN_FAILURE`, `PASSWORD_RESET`, `SUSPICIOUS_IP` 등 행동 유형을 등록하면 `SecurityLevelService`가 이벤트를 축적하고 등급/점수를 재계산합니다.
- "테넌트 세션 제한" 섹션은 최대 세션 수, 세션 유휴 시간(초), 최대 유지 시간(초)을 테넌트별로 저장하며 0 입력 시 해당 제한을 해제합니다.
- 정책 생성 폼에서는 `제외 그룹`, `제외 사용자`를 별도로 입력해 포함 대상과 겹치지 않는 범위에서 정책을 무시할 대상(화이트리스트)을 정의할 수 있습니다.

## API 기반 세션 시뮬레이션
관리 화면 외에도 간단한 테스트용 엔드포인트(`/session/mock`)가 제공됩니다. 예시는 아래와 같습니다.

```bash
curl "http://localhost:8080/session/mock?tenant=tenant1&user=alice&groups=engineering,security&country=KR"
```

요청이 성공하면 세션에 테넌트, 사용자, 그룹, 국가, 클라이언트 IP가 저장되며 이후 요청에서 정책 필터가 동일한 값을 사용합니다.

## 보안 레벨 구성
`security.level` 속성은 `src/main/resources/application.yml`에서 기본값을 정의합니다.
- `default-ttl`: 기본 세션 보안 상태 유지 시간 (기본 15분)
- `retention-events`: 최근 이벤트 최대 보존 개수 (기본 20개)
- `retention-window`: 이벤트 보존 기간 (기본 6시간)
- `policies`: 행동 유형별 보안 등급과 TTL(`LOGIN_FAILURE`, `PASSWORD_RESET`, `SUSPICIOUS_IP`, `DEVICE_CHANGE`, `UNKNOWN`)
필요 시 로컬 환경 변수나 `application-local.yml` 등을 통해 재정의하십시오.

## 테스트
통합 테스트는 `@ActiveProfiles("test")`를 사용하며, 내장 H2 데이터베이스와 Redis 대체 환경 없이 동작합니다.

```bash
./gradlew test
```

MySQL · Redis가 필요 없는 단위 테스트이지만, Spring 컨텍스트 로딩 시간이 길 경우 `--tests` 옵션으로 필요한 클래스만 실행할 수 있습니다.

## 빌드 & 패키징
```bash
./gradlew build
```
빌드 결과물은 `build/libs/security-0.0.1-SNAPSHOT.jar`에 생성되며, 동일한 외부 서비스(MySQL, Redis)를 기동한 뒤 `java -jar`로 실행할 수 있습니다.

## 문제 해결 팁
- 애플리케이션은 기동 시 스키마를 `create-drop`으로 초기화합니다. MySQL 데이터 유지를 원하면 `spring.jpa.hibernate.ddl-auto` 값을 `update`로 변경하고 수동으로 스키마를 관리하십시오.
- 세션 저장소는 Redis를 사용하므로 필터 동작을 확인할 때는 동일한 브라우저 세션 또는 `curl`에서 `--cookie-jar`를 사용해 세션 쿠키를 유지하십시오.
- `SessionPolicyFilter`가 접근을 차단할 경우 로그에 `AccessDeniedException`이 기록되며, 세션에는 마지막으로 평가된 정책 ID와 효과가 남습니다.
