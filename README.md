# 분산 인증 위임 시스템 (Auth-Chain)

이 프로젝트는 OAuth2 토큰 교환(RFC 8693) 표준을 사용하여 여러 마이크로서비스 간에 안전하게 인증을 위임하고 호출 체인을 관리하는 시스템의 C# 구현 예제입니다.

`Duende.IdentityServer`와 같은 외부 라이브러리에 의존하지 않고, 순수 .NET 라이브러리(`System.IdentityModel.Tokens.Jwt`)만을 사용하여 JWT 토큰 생성, 서명, 검증 및 토큰 교환, 토큰 검사(Introspection) 로직을 직접 구현했습니다.

## 시스템 아키텍처

이 시스템은 4개의 독립적인 웹 API 서비스로 구성됩니다.

1.  **TokenServer**: 중앙 인증 서버
    *   **역할**: 클라이언트 인증, JWT 토큰 발급, 토큰 교환, 토큰 검사(Introspection)를 담당합니다.
    *   **주요 엔드포인트**:
        *   `/connect/token`: `client_credentials` 및 `token_exchange` 부여 유형을 처리하여 토큰을 발급합니다.
        *   `/connect/introspect`: 토큰의 유효성을 검사하여 결과를 반환합니다.

2.  **SiteA**: 최초 호출 서비스
    *   **역할**: 외부로부터의 요청을 받아 가장 먼저 `TokenServer`에 자신을 위한 토큰(`Token_A`)을 요청하고, 이 토큰을 사용하여 `SiteB`를 호출하는 클라이언트입니다.

3.  **SiteB**: 중간 서비스 (위임자)
    *   **역할**: `SiteA`로부터 `Token_A`를 받아 유효성을 검증한 후, `TokenServer`에 `Token_A`를 제시하고 `SiteC`를 호출하기 위한 새로운 토큰(`Token_B_to_C`)으로 교환받습니다. 그 후, 교환받은 토큰으로 `SiteC`를 호출합니다.

4.  **SiteC**: 최종 자원 서버
    *   **역할**: `SiteB`로부터 `Token_B_to_C`를 받아, `TokenServer`의 토큰 검사(Introspection) 엔드포인트를 통해 최종적으로 유효성을 검증합니다. 검증이 완료되면 보호된 자원을 반환합니다.

## 핵심 동작 흐름 (A -> B -> C)

사용자가 `SiteA`의 엔드포인트를 호출했을 때의 전체 흐름은 다음과 같습니다.

1.  **[사용자 -> SiteA]**: 사용자가 `SiteA`의 `/call-b` 엔드포인트를 호출합니다.

2.  **[SiteA -> TokenServer]**: `SiteA`는 자신의 `client_id`와 `client_secret`을 사용하여 `TokenServer`의 `/connect/token` 엔드포인트에 `client_credentials` 방식으로 토큰(`Token_A`)을 요청합니다.
    *   `Token_A`의 대상(Audience)은 `api_b`로 지정됩니다.

3.  **[SiteA -> SiteB]**: `SiteA`는 발급받은 `Token_A`를 `Authorization: Bearer` 헤더에 담아 `SiteB`의 `/exchange/exchange-and-call-c` 엔드포인트를 호출합니다.

4.  **[SiteB (내부)]**: `SiteB`는 `Token_A`가 유효한지 로컬에서 검증합니다.

5.  **[SiteB -> TokenServer]**: `SiteB`는 검증된 `Token_A`를 `subject_token`으로 하여 `TokenServer`의 `/connect/token` 엔드포인트에 `token_exchange` 방식으로 새로운 토큰(`Token_B_to_C`)을 요청합니다.
    *   이때 `SiteB`는 자신의 `client_id`와 `client_secret`으로 자신을 인증합니다.
    *   `Token_B_to_C`의 대상(Audience)은 `api_c`로 지정됩니다.
    *   `TokenServer`는 새로 발급되는 `Token_B_to_C`에 `act` (actor) 클레임을 추가합니다. 이 클레임에는 최초 호출자인 `client_a`의 정보가 담겨있어 호출 체인을 증명합니다.

6.  **[SiteB -> SiteC]**: `SiteB`는 교환받은 `Token_B_to_C`를 `Authorization: Bearer` 헤더에 담아 `SiteC`의 `/data` 엔드포인트를 호출합니다.

7.  **[SiteC -> TokenServer]**: `SiteC`는 전달받은 `Token_B_to_C`를 `TokenServer`의 `/connect/introspect` 엔드포인트로 보내 유효성 검사를 요청합니다.
    *   이때 `SiteC`는 자신의 `client_id`와 `client_secret`으로 자신을 인증합니다.

8.  **[TokenServer -> SiteC]**: `TokenServer`는 토큰이 유효하다는 의미의 `{"active": true}`와 토큰에 포함된 클레임 정보를 `SiteC`에 반환합니다.

9.  **[SiteC -> SiteB -> SiteA -> 사용자]**: `SiteC`는 토큰이 유효함을 확인하고, 최종 결과 데이터를 생성하여 `SiteB`에게, `SiteB`는 `SiteA`에게, `SiteA`는 최종 사용자에게 응답을 전달합니다.

## 실행 및 테스트 방법

### 1. 전제 조건

*   .NET 11 (또는 프로젝트 파일에 명시된 버전) SDK

### 2. 서비스 실행

이 시스템은 4개의 서비스가 동시에 실행되어야 합니다. 4개의 개별 터미널을 열고, 프로젝트의 루트 디렉터리에서 각각 다음 명령을 실행하세요.

*   **터미널 1 (TokenServer):**
    ```shell
    dotnet run --project TokenServer
    ```

*   **터미널 2 (SiteA):**
    ```shell
    dotnet run --project SiteA
    ```

*   **터미널 3 (SiteB):**
    ```shell
    dotnet run --project SiteB
    ```

*   **터미널 4 (SiteC):**
    ```shell
    dotnet run --project SiteC
    ```

*참고: HTTPS 개발 인증서를 신뢰하라는 메시지가 표시되면 '예'를 선택하세요.*

### 3. 전체 흐름 테스트

모든 서비스가 실행되면, 웹 브라우저나 `curl`과 같은 API 테스트 도구를 사용하여 아래 URL로 `GET` 요청을 보냅니다.

*   **URL:** `https://localhost:7124/call-b`

호출이 성공하면, `SiteC`가 반환하는 아래와 같은 형식의 JSON 응답을 확인할 수 있습니다.

```json
{
  "message": "Hello from SiteC! Token validated via INTROSPECTION.",
  "caller_is_client": "client_b",
  "original_caller_was": "client_a",
  "all_claims_from_introspection": [
    /* ... 토큰에 포함된 전체 클레임 목록 ... */
  ]
}
```

이 응답은 전체 A -> B -> C 호출 체인이 성공적으로 동작했으며, `SiteC`가 토큰 검사를 통해 최종 호출자(`client_b`)와 최초 위임자(`client_a`)를 모두 인지했음을 증명합니다.
