# 診断観点カタログ (Perspectives Catalog)

133 のセキュリティ診断観点。OWASP ASVS **v5.0** / WSTG / CheatSheetSeries を統合。ASVS v5.0 の **17章構成** に沿って分類。**1観点 = 1ファイル** (`P<連番>-<英名>.md`)。各観点が Dynamic Workflow の1サブエージェントに対応する。

> 注: ASVS v5.0 は v4.0 から章番号と章名が大きく再編されています。本索引は v5.0 準拠です。

## メインエージェントの使い方

1. この README の索引を見て、対象コードに存在しない領域の観点を除外する。
2. 残りの `P<連番>-<英名>.md` を読み、各ファイルから以下を組み立てる:
   - `id` ← frontmatter `id`
   - `name` ← frontmatter `name`
   - `requires` ← frontmatter `requires`（必須タグ一覧。空配列 `[]` は全ユニットで実行）
   - `refs` ← frontmatter `refs`
   - `focus` ← `## What to check` 本文
   - `signals` ← `## Static signals` 本文
   - `fpNote` ← `## False positives` 本文
3. 組み立てた `perspectives[]` を `args.perspectives` として Workflow に渡す(`workflow-template.js` 参照)。

## 観点ファイルの形式

```markdown
---
id: P6
name: PasswordStrength
area: V6 Authentication
refs: ASVS V6.x / WSTG-ATHN-07 / CS: Password Storage
requires: [backend]
---

# PasswordStrength

## Overview
...
## What to check / ## Static signals / ## False positives / ## Attack scenario / ## Impact / ## Remediation / ## References
```

## 索引 (133観点 — ASVS v5.0 の17章構成)

### V1 Encoding and Sanitization
| ID | 名前 | ファイル |
|----|------|----------|
| P33 | SQLiStringConcat | P33-SQLiStringConcat.md |
| P34 | SQLiORM | P34-SQLiORM.md |
| P35 | NoSQLi | P35-NoSQLi.md |
| P36 | OSCommandInjection | P36-OSCommandInjection.md |
| P37 | LDAPXPathInjection | P37-LDAPXPathInjection.md |
| P38 | ReflectedXSS | P38-ReflectedXSS.md |
| P39 | StoredXSS | P39-StoredXSS.md |
| P41 | XXE | P41-XXE.md |
| P42 | InsecureDeserialization | P42-InsecureDeserialization.md |
| P43 | SSTI | P43-SSTI.md |
| P44 | SSRF | P44-SSRF.md |
| P45 | PathTraversal | P45-PathTraversal.md |
| P46 | OpenRedirect | P46-OpenRedirect.md |
| P47 | ResponseSplitting | P47-ResponseSplitting.md |
| P48 | ReDoS | P48-ReDoS.md |
| P49 | HostHeaderInjection | P49-HostHeaderInjection.md |
| P50 | MassAssignment | P50-MassAssignment.md |
| P118 | PrototypePollution | P118-PrototypePollution.md |
| P131 | EmailHeaderInjection | P131-EmailHeaderInjection.md |

### V2 Validation and Business Logic
| ID | 名前 | ファイル |
|----|------|----------|
| P80 | PriceQuantityTrust | P80-PriceQuantityTrust.md |
| P81 | StateTransitionBypass | P81-StateTransitionBypass.md |
| P82 | RaceCondition | P82-RaceCondition.md |
| P83 | CouponReuse | P83-CouponReuse.md |
| P84 | LimitBypass | P84-LimitBypass.md |
| P85 | NonRepudiation | P85-NonRepudiation.md |
| P128 | CSVFormulaInjection | P128-CSVFormulaInjection.md |
| P129 | HTTPParameterPollution | P129-HTTPParameterPollution.md |

### V3 Web Frontend Security
| ID | 名前 | ファイル |
|----|------|----------|
| P40 | DOMXSS | P40-DOMXSS.md |
| P119 | ClientSideStorage | P119-ClientSideStorage.md |
| P120 | Clickjacking | P120-Clickjacking.md |
| P124 | PostMessageOrigin | P124-PostMessageOrigin.md |
| P125 | SubresourceIntegrity | P125-SubresourceIntegrity.md |
| P126 | ServiceWorkerSecurity | P126-ServiceWorkerSecurity.md |
| P127 | TrustedTypesStrictCSP | P127-TrustedTypesStrictCSP.md |
| P130 | ReverseTabnabbing | P130-ReverseTabnabbing.md |

### V4 API and Web Service
| ID | 名前 | ファイル |
|----|------|----------|
| P93 | RESTBOLA | P93-RESTBOLA.md |
| P94 | RESTExposureMassAssignment | P94-RESTExposureMassAssignment.md |
| P95 | RESTRateLimit | P95-RESTRateLimit.md |
| P96 | GraphQLIntrospection | P96-GraphQLIntrospection.md |
| P97 | GraphQLComplexity | P97-GraphQLComplexity.md |
| P98 | GraphQLBOLA | P98-GraphQLBOLA.md |
| P99 | GraphQLBatching | P99-GraphQLBatching.md |
| P100 | LegacyEndpoint | P100-LegacyEndpoint.md |
| P101 | gRPCWebSocketAuth | P101-gRPCWebSocketAuth.md |
| P114 | WebSocketSecurity | P114-WebSocketSecurity.md |

### V5 File Handling
| ID | 名前 | ファイル |
|----|------|----------|
| P86 | UploadValidation | P86-UploadValidation.md |
| P87 | UploadPathExecution | P87-UploadPathExecution.md |
| P88 | FileAccessTraversal | P88-FileAccessTraversal.md |
| P89 | FileDoS | P89-FileDoS.md |
| P90 | ExternalResourceFetch | P90-ExternalResourceFetch.md |
| P91 | TempFileProtection | P91-TempFileProtection.md |
| P92 | LFIRFI | P92-LFIRFI.md |
| P132 | ArchiveExtractionSlip | P132-ArchiveExtractionSlip.md |

### V6 Authentication
| ID | 名前 | ファイル |
|----|------|----------|
| P6 | PasswordStrength | P6-PasswordStrength.md |
| P7 | PasswordHashing | P7-PasswordHashing.md |
| P8 | AuthRateLimit | P8-AuthRateLimit.md |
| P9 | UserEnumeration | P9-UserEnumeration.md |
| P10 | SessionGeneration | P10-SessionGeneration.md |
| P11 | MFA | P11-MFA.md |
| P12 | CredentialTransport | P12-CredentialTransport.md |
| P13 | PasswordReset | P13-PasswordReset.md |
| P14 | JWTValidation | P14-JWTValidation.md |
| P15 | DefaultCredentials | P15-DefaultCredentials.md |

### V7 Session Management
| ID | 名前 | ファイル |
|----|------|----------|
| P16 | SessionIDEntropy | P16-SessionIDEntropy.md |
| P17 | SessionCookieAttributes | P17-SessionCookieAttributes.md |
| P18 | SessionTimeout | P18-SessionTimeout.md |
| P19 | SessionRegeneration | P19-SessionRegeneration.md |
| P20 | SessionInvalidation | P20-SessionInvalidation.md |
| P21 | ConcurrentSessions | P21-ConcurrentSessions.md |
| P22 | SessionStoreProtection | P22-SessionStoreProtection.md |
| P23 | CSRFProtection | P23-CSRFProtection.md |

### V8 Authorization
| ID | 名前 | ファイル |
|----|------|----------|
| P24 | IDOR | P24-IDOR.md |
| P25 | ServerSideAuthz | P25-ServerSideAuthz.md |
| P26 | HorizontalVerticalAuthz | P26-HorizontalVerticalAuthz.md |
| P27 | ForcedBrowsing | P27-ForcedBrowsing.md |
| P28 | DenyByDefault | P28-DenyByDefault.md |
| P29 | MultiTenantIsolation | P29-MultiTenantIsolation.md |
| P30 | FunctionLevelAuthz | P30-FunctionLevelAuthz.md |
| P31 | AuthzTOCTOU | P31-AuthzTOCTOU.md |
| P32 | PropertyLevelAuthz | P32-PropertyLevelAuthz.md |

### V9 Self-contained Tokens
| ID | 名前 | ファイル |
|----|------|----------|
| P123 | SelfContainedTokens | P123-SelfContainedTokens.md |

### V10 OAuth and OIDC
| ID | 名前 | ファイル |
|----|------|----------|
| P110 | OAuth2AuthCodeFlow | P110-OAuth2AuthCodeFlow.md |
| P111 | OIDCIDTokenValidation | P111-OIDCIDTokenValidation.md |
| P112 | OAuthTokenHandling | P112-OAuthTokenHandling.md |
| P113 | SAMLSecurity | P113-SAMLSecurity.md |

### V11 Cryptography
| ID | 名前 | ファイル |
|----|------|----------|
| P51 | WeakAlgorithms | P51-WeakAlgorithms.md |
| P52 | HardcodedKeys | P52-HardcodedKeys.md |
| P53 | IVNonceSalt | P53-IVNonceSalt.md |
| P54 | TimingAttack | P54-TimingAttack.md |
| P55 | PredictableRandom | P55-PredictableRandom.md |
| P56 | KeyManagement | P56-KeyManagement.md |
| P57 | HMACSignatureVerification | P57-HMACSignatureVerification.md |

### V12 Secure Communication
| ID | 名前 | ファイル |
|----|------|----------|
| P71 | TLSEnforcement | P71-TLSEnforcement.md |
| P72 | HSTS | P72-HSTS.md |
| P73 | CertValidationDisabled | P73-CertValidationDisabled.md |
| P74 | MixedContent | P74-MixedContent.md |
| P75 | InternalTransportEncryption | P75-InternalTransportEncryption.md |

### V13 Configuration
| ID | 名前 | ファイル |
|----|------|----------|
| P102 | DefaultConfigCredentials | P102-DefaultConfigCredentials.md |
| P103 | DebugMode | P103-DebugMode.md |
| P104 | CORSOverPermissive | P104-CORSOverPermissive.md |
| P105 | SecurityHeaders | P105-SecurityHeaders.md |
| P106 | ConfigFileSecrets | P106-ConfigFileSecrets.md |
| P107 | AdminInterfaceExposure | P107-AdminInterfaceExposure.md |
| P108 | BannerInfoExposure | P108-BannerInfoExposure.md |
| P109 | CookieSessionStoreConfig | P109-CookieSessionStoreConfig.md |
| P115 | HTTPRequestSmuggling | P115-HTTPRequestSmuggling.md |
| P116 | WebCachePoisoning | P116-WebCachePoisoning.md |
| P117 | SubdomainTakeover | P117-SubdomainTakeover.md |
| P121 | CloudStorageExposure | P121-CloudStorageExposure.md |

### V14 Data Protection
| ID | 名前 | ファイル |
|----|------|----------|
| P65 | DataMasking | P65-DataMasking.md |
| P66 | TempDataCaching | P66-TempDataCaching.md |
| P67 | MemoryClearing | P67-MemoryClearing.md |
| P68 | BackupProtection | P68-BackupProtection.md |
| P69 | PIIOverCollection | P69-PIIOverCollection.md |
| P70 | ExcessiveDataExposure | P70-ExcessiveDataExposure.md |

### V15 Secure Coding and Architecture
| ID | 名前 | ファイル |
|----|------|----------|
| P1 | TrustBoundary | P1-TrustBoundary.md |
| P2 | LayerSeparation | P2-LayerSeparation.md |
| P3 | MinimalExposure | P3-MinimalExposure.md |
| P4 | DependencyVerification | P4-DependencyVerification.md |
| P5 | SecureDefaults | P5-SecureDefaults.md |
| P76 | DebugBackdoor | P76-DebugBackdoor.md |
| P77 | EvalDynamicExecution | P77-EvalDynamicExecution.md |
| P78 | BackdoorCredentials | P78-BackdoorCredentials.md |
| P79 | SuspiciousDependencies | P79-SuspiciousDependencies.md |
| P133 | ContainerSecurity | P133-ContainerSecurity.md |

### V16 Security Logging and Error Handling
| ID | 名前 | ファイル |
|----|------|----------|
| P58 | StackTraceExposure | P58-StackTraceExposure.md |
| P59 | GlobalExceptionHandler | P59-GlobalExceptionHandler.md |
| P60 | SensitiveDataLogging | P60-SensitiveDataLogging.md |
| P61 | LogInjection | P61-LogInjection.md |
| P62 | AuditTrail | P62-AuditTrail.md |
| P63 | LogTamperProtection | P63-LogTamperProtection.md |
| P64 | TimestampCorrelationID | P64-TimestampCorrelationID.md |

### V17 WebRTC
| ID | 名前 | ファイル |
|----|------|----------|
| P122 | WebRTC | P122-WebRTC.md |

## 参照資料

- OWASP ASVS v5.0.0: https://github.com/OWASP/ASVS/tree/v5.0.0/5.0
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/latest/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/index.html

> `refs` 欄の ASVS/WSTG/CS ID は知識ベースに基づく。ASVS v5.0 で章番号が再編されているため、最新の正確な要件番号は公式資料で照合すること。
