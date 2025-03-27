# labid (very WIP)

Signed JWT token exchange service


```mermaid
sequenceDiagram
    participant GKE
    participant Client
    participant labid
    participant Service
    GKE->>Client: Provides native JWT token
    Client->>labid: Requests exchange of native JWT for labid token at /token
    labid-->>GKE: Checks validity of native token against JWKS
    labid-->>GKE: Deduces Dapla group based on Client's SA annotations
    labid->>Client: Response with JWT token
    Client->>Service: Request with token from labid
    Service-->>labid: Checks validity of labid token against JWKS (/jwks)
```
