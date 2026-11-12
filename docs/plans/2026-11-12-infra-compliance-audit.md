# Skill `auditing-infra-compliance`: plan de implementación

> **Para agentes que lo ejecuten:** SUB-SKILL OBLIGATORIO. Usar `superpowers:subagent-driven-development`
> (recomendado) o `superpowers:executing-plans` para implementar este plan tarea por tarea. Los pasos usan
> casillas (`- [ ]`) para el seguimiento.

**Objetivo:** construir un skill de Claude Code. A partir de un vault de Obsidian y/o credenciales AWS de
solo lectura, el skill audita infraestructura AWS contra SOC 2 e ISO 27001:2022 y produce un `.html`
autocontenido con comandos de CloudShell copiables para arreglar cada hallazgo.

**Arquitectura:**
- Los scripts Python determinísticos hacen todo lo verificable:
  - `vault_index.py` lee el vault;
  - `collect.py` ejecuta chequeos AWS de solo lectura con allowlist;
  - `assemble_findings.py` combina y mapea;
  - `render_report.py` genera el HTML.
- Claude orquesta y aporta el juicio:
  - resuelve el alcance y la feature;
  - compara vault contra realidad, en `vault-claims.json`;
  - evalúa los pocos chequeos `evaluator: "claude"`.
- El catálogo de chequeos es JSON por dominio. Los mapeos SOC 2/ISO de los tests de Drata salen del archivo
  DCF embebido.

**Stack:** Python ≥ 3.10, solo stdlib en runtime. AWS CLI v2. `unittest` para las pruebas. HTML, CSS y JS
inline. Markdown para el SKILL y las referencias.

**Spec:** `docs/specs/2026-11-12-infra-compliance-audit-design.md`. Investigación de soporte en
`docs/research/`: `vanta-drata-tests.md`, `frameworks-aws-mapping.md`, `drata-dcf-mapping.json`,
`soc2-reference-infrastructures.md`, `github-skill-review.md`.

## Restricciones globales

**Seguridad y ejecución**
- **Nunca se ejecuta una operación AWS de escritura.**
  - `awscli.assert_read_only` admite solo operaciones que empiecen con `describe-`, `list-` o `get-`, o
    que sean exactamente `lookup-events` o `generate-credential-report`.
  - Todo par de la denylist (Tarea 3) se rechaza aunque cumpla el prefijo.
- `subprocess` siempre con lista de argumentos y `shell=False`.
- **Nunca** se leen archivos `.env*`, `~/.aws/credentials`, `*.pem` ni `*.key`.
  - `vault_index.py` ignora todo archivo que no sea `.md` y todo archivo o carpeta que empiece con `.`,
    salvo `.obsidian/` (solo se lista).
- Los comandos de remediación **nunca** se ejecutan; solo se escriben en `findings.json` y en el HTML.
- **Enmascarado en todo lo que se escribe a disco o al HTML:**
  - claves `AKIA`/`ASIA` → `AKIA…WXYZ` (4 últimos caracteres);
  - emails → `u***@dominio`, salvo valores del tag `VantaOwner`;
  - `aws_secret_access_key=...` y similares → `[REDACTED]`.
- **Ningún archivo del repo contiene un literal con forma de access key.** Hay un hook que lo bloquea.
  Las claves ficticias de las pruebas se arman en tiempo de ejecución concatenando partes, por ejemplo
  `"AKIA" + "TESTKEYABCDEMNOP"`. Las notas de vault que las contienen se generan en un directorio temporal
  con `tests/helpers.make_secret_note(dir)`.

**Entorno**
- Runtime: Python ≥ 3.10, sin dependencias fuera de la stdlib.
- Pruebas: `python3 -m unittest discover -s tests -v`.
- Plataformas: Linux y macOS. Windows queda fuera.

**Reporte**
- Salida: `./compliance-reports/<plataforma>-<alcance>-<YYYY-MM-DD-HHMM>/` con `report.html`,
  `findings.json`, `checks-result.json`, `inventory.json` y `raw/`. Nunca dentro del vault.
- El HTML no carga recursos externos: ningún `<script src>`, `<link href>` ni `<img src>` con `http`.
  Los links `<a href>` a fuentes sí están permitidos.
- Idioma por defecto del HTML: castellano. IDs, comandos y nombres de tests quedan en su idioma original.
- Sin porcentaje ni nota global de cumplimiento en ningún lugar.

**Modelo de datos**
- Severidades: `critical` | `high` | `medium` | `low`.

| Severidad | Cuándo |
|---|---|
| `critical` | Exposición pública de datos o de credenciales; root sin MFA o con access keys |
| `high` | Falla un test automático de Drata o Vanta |
| `medium` | Control de Security Hub, CIS o FSBP relevante, sin test de Drata/Vanta |
| `low` | Higiene |

- Estados: `FAIL`, `PASS`, `DRIFT`, `DOCUMENTED_ONLY`, `DOCUMENTED_GAP`, `UNDOCUMENTED`, `NO_VERIFICADO`,
  `N/A`.
- `remediation.kind`: `cli` | `cli_with_decision` | `planned_change` | `console_only`.
- `remediation.risk`: `low` | `medium` | `high`.
- **Mapeos:**
  - todo ID TSC o ISO debe existir en `references/frameworks/`;
  - los mapeos SOC 2/ISO de chequeos con test de Drata presente en `drata-dcf.json` se resuelven desde
    ese archivo (`sourced: "drata-dcf-2026-11-12"`);
  - el resto lleva `sourced: false` y se muestra como "inferido".
- **Pase vacío:** si no hay recursos del tipo del chequeo en el alcance, el estado es `N/A` con
  `vacuous: true`. Nunca `PASS`.

**Contenido del repositorio**
- El repo no contiene referencias a proyectos, cuentas, buckets ni personas reales.
- Los fixtures usan la plataforma ficticia **"Acme Notes"**, la cuenta `111122223333`, la región
  `us-east-1` y el dominio `acme-notes.example`.
- Texto de AICPA e ISO: solo IDs y nombres cortos parafraseados.

**Placeholders en comandos de CloudShell**
- Formato `__COMPLETAR_<NOMBRE>__`, por ejemplo `__COMPLETAR_OWNER_EMAIL__`.
- **Desviación de la spec:** la spec decía `<<COMPLETAR: …>>`, pero en bash `<<` abre un heredoc, y pegarlo
  deja CloudShell colgado esperando el terminador.
- Variables al inicio de cada bloque: `REGION="…"` y `ACCOUNT_ID="…"`. Sin `set -e`, porque cerraría la
  sesión de CloudShell ante el primer error.

**Git**
- Repo local nuevo, rama `feature/auditing-infra-compliance`, commits convencionales (`feat:`, `test:`,
  `chore:`, `docs:`).
- Sin push.
- Cada commit termina con la línea de co-autoría:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Foco de revisión

1. **Permisos parciales.** Una llamada con `AccessDenied` debe producir `NO_VERIFICADO` con el permiso
   faltante, nunca `PASS` ni `FAIL`. Se fija en la Tarea 4 con `test_access_denied_is_not_verified`.
2. **Servicio no habilitado.** GuardDuty, Security Hub, Config o Inspector apagados devuelven
   `NOT_ENABLED`, y para los chequeos de habilitación eso es `FAIL`, no `NO_VERIFICADO`. Se fija en la
   Tarea 4 con `test_not_enabled_means_fail_when_declared`.
3. **Secretos en el vault.** Una nota con una access key o un `aws_secret_access_key` no debe aparecer en
   claro en `vault-index.json`, `findings.json` ni el HTML. Se fija en las Tareas 12 y 13 con
   `test_masks_keys_in_index` y `test_findings_are_masked`.
4. **Nombres hostiles.** Nombres de recurso o valores de tag con `<script>`, `"`, `</script>` o backticks
   deben quedar escapados en el HTML y en los bloques copiables. Se fija en la Tarea 14 con
   `test_hostile_names_escaped`.
5. **Cuenta grande.** Con muchas regiones y cientos de recursos, la salida de `collect.py` al terminal
   tiene que ser un resumen de ≤ 40 líneas para no llenar el contexto de Claude; el detalle va a disco. Se
   fija en la Tarea 4 con `test_stdout_summary_is_bounded`.

---

## Estructura de archivos

```
infra-compliance-audit/
  README.md                                   qué es, instalación (symlink a ~/.claude/skills), uso, pruebas
  .gitignore                                  compliance-reports/, __pycache__/, *.pyc
  docs/specs/… docs/research/… docs/plans/…   (existentes)
  auditing-infra-compliance/
    SKILL.md                                  flujo procedural (Tarea 15)
    references/
      vault-reading.md                        contrato tipado, heurísticas libres, feature/recurso (T15)
      remediation-guidelines.md               reglas CloudShell, placeholders, planned_change (T15)
      report-format.md                        esquemas scope.json, vault-claims.json, findings.json (T15)
      drata-vanta.md                          roles, permisos, tags, pase vacío, fase 2 (T15)
      inventory.json                          tipos de recurso → llamada de listado (T4)
      checks/{iam,logging,detection,compute,encryption,network,data,monitoring,inventory,
              integration,email}.json         catálogo (T5–T11)
      frameworks/iso27001-2022.json           93 controles Anexo A + cláusulas 4–10 (T1)
      frameworks/tsc-2017.json                61 criterios (T1)
      mappings/drata-dcf.json                 copia de docs/research/drata-dcf-mapping.json (T1)
    scripts/
      catalog.py                              constantes, carga y validación del catálogo, mapeos (T2)
      validate_catalog.py                     CLI del validador (T2)
      awscli.py                               runner de solo lectura, errores, reintentos, dns (T3)
      paths.py                                extract(data, path) con mini-lenguaje de rutas (T4)
      collect.py                              inventario + ejecución de chequeos (T4)
      evaluators.py                           registro de evaluadores python:<nombre> (T4, T5–T11)
      vault_index.py                          índice del vault + resolución de feature (T12)
      redact.py                               enmascarado (T12 mínimo, T13 completo)
      assemble_findings.py                    findings.json (T13)
      render_report.py                        HTML (T14)
    assets/report-template.html               plantilla (T14)
  tests/
    helpers.py                                FakeRunner, load_fixture, make_secret_note
    fixtures/aws/<dominio>/*.json             respuestas AWS ficticias (Acme Notes)
    fixtures/typed-vault/ fixtures/free-vault/
    fixtures/scope-*.json fixtures/vault-claims.json fixtures/findings-sample.json
    test_frameworks.py test_catalog.py test_awscli.py test_paths.py test_collect.py
    test_eval_<dominio>.py test_vault_index.py test_redact.py test_assemble.py test_render.py test_e2e.py
    skill-scenarios.md
```

Rutas de los scripts en los comandos: relativas a `infra-compliance-audit/`. `SKILL_DIR` =
`auditing-infra-compliance`.

---

### Tarea 1: bootstrap del repo y catálogos de normas

**Archivos:**
- Crear: `.gitignore`, `README.md` (esqueleto: título, una línea de propósito; se completa en la T16)
- Crear: `auditing-infra-compliance/references/frameworks/iso27001-2022.json`
- Crear: `auditing-infra-compliance/references/frameworks/tsc-2017.json`
- Crear: `auditing-infra-compliance/references/mappings/drata-dcf.json` (copia exacta de
  `docs/research/drata-dcf-mapping.json`)
- Prueba: `tests/test_frameworks.py`

**Interfaces:**
- **Produce `iso27001-2022.json`:**
  ```
  {"version": "ISO/IEC 27001:2022",
   "clauses": [{"id": "4.1", "name": …}, …],                    // 4.1 … 10.2
   "controls": [{"id": "A.5.1", "theme": "organizational|people|physical|technological",
                 "name": "<paráfrasis corta>",
                 "responsibility": "customer|shared|inherited",
                 "technical": bool}, …]}
  ```
  - `technical: true` = el skill puede aportar evidencia técnica: 5.9, 5.15–5.18, 5.23, 5.33, 8.x salvo
    8.1, 8.4, 8.7, 8.25–8.31 y 8.33.
  - `responsibility` según `frameworks-aws-mapping.md` §5: 7.x en lo que se aloja en AWS → `inherited`; 7.x
    de oficinas o equipos propios → `shared`.
- **Produce `tsc-2017.json`:**
  ```
  {"version": "TSC 2017 (rev. 2022 PoF)",
   "criteria": [{"id": "CC6.1", "category": "security|availability|confidentiality|processing_integrity|privacy",
                 "name": …, "technical": bool}, …]}
  ```
- La fuente de la lista y los nombres es `docs/research/frameworks-aws-mapping.md` §1.1, §1.3, §2.1 y §2.2.

- [ ] **Paso 1:** `git init`, crear la rama `feature/auditing-infra-compliance`, crear `.gitignore` con
  `compliance-reports/`, `__pycache__/` y `*.pyc`, crear `README.md` esqueleto.
- [ ] **Paso 2: escribir las pruebas que fallan** en `tests/test_frameworks.py`:
  - `test_iso_has_93_controls_by_theme`: conteo total 93; por tema: organizational 37, people 8,
    physical 14, technological 34;
  - `test_iso_new_2022_controls_present`: existen A.5.7, A.5.23, A.5.30, A.7.4, A.8.9, A.8.10, A.8.11,
    A.8.12, A.8.16, A.8.23 y A.8.28;
  - `test_iso_clauses_cover_4_to_10`: existen 4.1 y 10.2, y ningún ID repetido;
  - `test_tsc_has_61_criteria`: 61 en total, 33 `CC*`, IDs únicos; existen `A1.3`, `C1.2`, `PI1.5` y
    `P8.1`; **no** existe `C1.3`;
  - `test_physical_controls_not_customer_only`: todo `A.7.*` tiene `responsibility` en {`inherited`,
    `shared`};
  - `test_drata_dcf_copied`: `mappings/drata-dcf.json` es idéntico a `docs/research/drata-dcf-mapping.json`
    y tiene 130 tests.
- [ ] **Paso 3:** correr `python3 -m unittest tests.test_frameworks -v`. Esperado: FAIL (archivos
  inexistentes).
- [ ] **Paso 4:** crear los tres JSON con nombres parafraseados.
- [ ] **Paso 5:** correr las pruebas. Esperado: 6 OK.
- [ ] **Paso 6:** hacer commit con `chore: bootstrap repo and framework catalogs`.

---

### Tarea 2: esquema del catálogo, resolución de mapeos y validador

**Archivos:**
- Crear: `auditing-infra-compliance/scripts/catalog.py`
- Crear: `auditing-infra-compliance/scripts/validate_catalog.py`
- Prueba: `tests/test_catalog.py`, `tests/fixtures/catalog-min/test.json`

**Interfaces:**
- **Produce, en `catalog.py`:**
  - Constantes `SEVERITIES`, `STATUSES`, `REMEDIATION_KINDS`, `RISKS`, `EVALUATOR_KINDS = ("jmespath",
    "python", "claude", "dns")` y `DCF_SOURCE = "drata-dcf-2026-11-12"`.
  - `load_checks(checks_dir: Path) -> list[dict]`: une todos los `*.json` de la carpeta; cada archivo es
    `{"domain": str, "checks": [...]}`.
  - `load_frameworks(frameworks_dir: Path) -> tuple[set[str], set[str]]`: devuelve los IDs TSC y los IDs
    ISO; en estos últimos, Anexo A y cláusulas.
  - `load_drata_map(path: Path) -> dict[int, dict]`: indexado por `test_id`.
  - `resolve_mappings(check: dict, drata: dict[int, dict]) -> dict`: devuelve
    `{"drata": [...], "vanta": [...], "tsc": [{"id", "sourced"}], "iso27001_2022": [...], "security_hub": [...], "cis_aws": [...]}`.
    - Si algún test de `check["mappings"]["drata"]` está en `drata`, toma la unión de `soc2` e
      `iso27001_2022` de sus controles con `sourced = DCF_SOURCE`.
    - Si no, usa `check["mappings"]["tsc_inferred"]` e `iso_inferred` con `sourced: false`.
  - `validate(checks, tsc_ids, iso_ids, drata) -> list[str]`: devuelve los mensajes de error; lista vacía
    significa válido.
- **Esquema de un chequeo** (todos los campos son obligatorios salvo los marcados como opcionales):
  ```
  {"id": "IAM-001", "title": str (castellano), "domain": str,
   "scope": "account|resource",
   "resource_types": [str],                      // claves de inventory.json; [] para scope account
   "account_context_for": [str],                 // opcional: tipos para los que este chequeo de cuenta aplica en modo feature/resource
   "all_regions": bool,                          // corre en todas las regiones habilitadas
   "severity": …, "not_enabled_means": "fail|not_verified",
   "verify": {"calls": [Call], "evaluator": "jmespath|python:<nombre>|claude|dns",
              "offenders": str,                  // expresión JMESPath (solo si evaluator == jmespath y 1 call)
              "params": {…},                     // opcional, para evaluadores python
              "pass_when_text": str, "needs": ["svc:Action", …]},
   "vault_signals": [str],
   "mappings": {"drata": [{"test": int, "name": str, "source": url}],
                "vanta": [{"test": str, "source": url}],
                "tsc_inferred": [str], "iso_inferred": [str],
                "security_hub": [str], "cis_aws": [str]},
   "remediation": {"kind": …, "risk": …, "downtime": bool,
                   "steps": [str], "commands": [str], "verify_after": str, "notes": str},
   "sources": [url]}
  ```
  - `Call = {"name": str, "service": str, "operation": str, "args": [str], "region": "global|each",
    "for_each": {"from": <call name>, "path": <ruta paths.py>, "arg": "--flag"}}`. El `for_each` es
    opcional.
- **Reglas de `validate`**, una prueba por regla:
  1. IDs únicos con formato `^[A-Z]{3}-\d{3}$`.
  2. Severidad, kind, risk y evaluador válidos.
  3. Cada `(service, operation)` de `calls` pasa `awscli.assert_read_only` (se importa en la Tarea 3; en
     esta tarea se usa un stub local `_is_read_only` con las mismas reglas de prefijo, que la Tarea 3
     reemplaza por el import).
  4. Todo `tsc_inferred` existe en TSC y todo `iso_inferred` en ISO.
  5. Todo `mappings.drata[].test` es int.
  6. Si `evaluator == "jmespath"`: hay exactamente 1 call y `offenders` no está vacío.
  7. `remediation.verify_after` no vacío, salvo `console_only`.
  8. `planned_change` tiene ≥ 2 `steps` y `notes` no vacío (la advertencia).
  9. `commands` no contiene `<<`.
  10. Si un chequeo no tiene test de Drata resoluble en el DCF, tiene ≥ 1 `tsc_inferred` y ≥ 1
      `iso_inferred`.
  11. `scope == "resource"` implica `resource_types` no vacío.
- **`validate_catalog.py`:** CLI sin argumentos. Carga desde `SKILL_DIR/references`, imprime los errores y
  sale con código 1 si hay errores, 0 si no. Última línea: `OK: <n> checks`.

- [ ] **Paso 1: escribir las pruebas que fallan** en `tests/test_catalog.py` con el fixture
  `catalog-min/test.json`, que tiene 2 chequeos válidos: uno con Drata 214 y otro sin Drata.
  - `test_valid_catalog_has_no_errors`.
  - `test_resolve_mappings_from_dcf`: el chequeo con Drata 214 resuelve TSC {CC6.1, CC7.2} e ISO
    {A.8.2, A.8.16} con `sourced == DCF_SOURCE`.
  - `test_resolve_mappings_inferred`: sourced `False`.
  - Una prueba `test_rule_<n>_…` por cada regla del 1 al 11. Cada una muta el fixture y espera ≥ 1 error
    que contenga el ID del chequeo. Ejemplos:
    - `test_rule_3_rejects_write_operation` con `ec2 modify-instance-attribute`;
    - `test_rule_9_rejects_heredoc_placeholder`.
- [ ] **Paso 2:** correr `python3 -m unittest tests.test_catalog -v`. Esperado: FAIL (import error).
- [ ] **Paso 3:** implementar `catalog.py` y `validate_catalog.py`.
- [ ] **Paso 4:** correr las pruebas. Esperado: todas OK.
- [ ] **Paso 5:** hacer commit con `feat: catalog schema, mapping resolution and validator`.

---

### Tarea 3: runner AWS de solo lectura

**Archivos:**
- Crear: `auditing-infra-compliance/scripts/awscli.py`
- Modificar: `scripts/catalog.py` (reemplazar el stub `_is_read_only` por `awscli.assert_read_only`)
- Prueba: `tests/test_awscli.py`, `tests/helpers.py`

**Interfaces:**
- **Produce:**
  - `class ReadOnlyViolation(Exception)`.
  - `ALLOWED_PREFIXES = ("describe-", "list-", "get-")`.
  - `ALLOWED_EXACT = frozenset({"lookup-events", "generate-credential-report"})`.
  - `DENYLIST` (frozenset de pares `(service, operation)`; `"*"` como operación bloquea todo el servicio):
    - `("secretsmanager","get-secret-value")`;
    - `("ssm","get-parameter")`, `("ssm","get-parameters")`, `("ssm","get-parameters-by-path")`;
    - `("lambda","get-function")`;
    - `("s3api","get-object")`, `("s3api","get-object-torrent")`;
    - `("kms","decrypt")`, `("kms","generate-data-key")`, `("kms","generate-data-key-without-plaintext")`;
    - `("ecr","get-login-password")`, `("ecr","get-authorization-token")`;
    - `("sts","get-session-token")`, `("sts","get-federation-token")`;
    - `("logs","get-log-events")`, `("logs","filter-log-events")`;
    - `("dynamodb","get-item")`, `("dynamodb","scan")`, `("dynamodb","query")`,
      `("dynamodb","batch-get-item")`;
    - `("ec2","get-password-data")`;
    - `("rds-data","*")`, `("s3","*")`.
  - `FORBIDDEN_ARGS = frozenset({"--with-decryption"})`.
  - `assert_read_only(service: str, operation: str, args: list[str]) -> None`: lanza `ReadOnlyViolation`
    con el motivo.
  - `@dataclass(frozen=True) class CallResult`: `ok: bool`, `data: object | None`, `error_kind: str |
    None` (`ACCESS_DENIED`, `NOT_ENABLED`, `NO_CREDENTIALS`, `THROTTLED`, `ERROR`), `error_message: str |
    None`, `argv: tuple[str, ...]`.
  - `run_aws(service, operation, args, *, region: str | None, profile: str | None, query: str | None =
    None, runner=subprocess.run, sleep=time.sleep) -> CallResult`.
    - argv = `["aws", service, operation, *args, "--output", "json"]`, más `--region`, `--profile` y
      `--query` si están dados.
    - `assert_read_only` antes de ejecutar.
    - Timeout de 120 s.
    - Throttling: 4 reintentos con backoff de 1, 2, 4 y 8 s.
  - `classify_error(stderr: str) -> str`:

| Patrón en stderr | Resultado |
|---|---|
| `AccessDenied`, `UnauthorizedOperation`, `AccessDeniedException`, `not authorized to perform` | `ACCESS_DENIED` |
| `OptInRequired`, `SubscriptionRequiredException`, `InvalidAccessException` (Security Hub), `is not subscribed`, `NoSuchConfigurationRecorder`, `BadRequestException` con "not enabled" | `NOT_ENABLED` |
| `Unable to locate credentials`, `ExpiredToken`, `InvalidClientTokenId`, `could not be found` (perfil inexistente) | `NO_CREDENTIALS` |
| `Throttling`, `Rate exceeded`, `TooManyRequests` | `THROTTLED` |
| cualquier otro | `ERROR` |

  - `run_dns(name: str, rrtype: str, runner=subprocess.run, which=shutil.which) -> CallResult`: usa
    `["dig", "+short", rrtype, name]` o, si no está, `["nslookup", "-type=" + rrtype, name]`. `data` es la
    lista de líneas de respuesta. Si no hay ninguno de los dos: `error_kind="ERROR"`, mensaje
    `"dig/nslookup no disponibles"`.
- **Produce, en `tests/helpers.py`:**
  - `class FakeRunner`: callable que imita `subprocess.run`. Se inicializa con
    `{(service, operation, region|None): {"stdout": str, "stderr": str, "returncode": int}}` y registra
    cada argv en `self.calls`. Una entrada puede ser una lista de respuestas, que se consumen en orden.
  - `load_fixture(rel: str) -> object`.
  - `make_secret_note(dir: Path) -> Path`: escribe una nota `.md` con `aws_access_key_id = ` seguido de
    una clave armada en runtime (`"AKIA" + "TESTKEYABCDEMNOP"`). Devuelve la ruta.

- [ ] **Paso 1: escribir las pruebas que fallan:**
  - `test_allows_describe_list_get` (3 casos) y `test_allows_exact_exceptions`;
  - `test_rejects_write_ops`: `ec2 modify-instance-metadata-options`, `iam create-user`,
    `s3api put-bucket-policy`, `iam delete-access-key`, `cloudtrail start-logging`;
  - `test_rejects_denylist`: cada par de `DENYLIST`, incluido `rds-data execute-statement` y
    `s3 ls` (por el comodín `*`);
  - `test_rejects_with_decryption`;
  - `test_never_uses_shell`: `FakeRunner` verifica que el kwarg `shell` no sea `True` y que argv sea una
    lista;
  - `test_classify_error_table`: una aserción por fila de la tabla;
  - `test_throttling_retries_then_succeeds`: 2 respuestas de throttling y luego OK; `sleep` falso
    registra `[1, 2]`;
  - `test_access_denied_not_retried`;
  - `test_query_and_region_in_argv`;
  - `test_dns_falls_back_to_nslookup`;
  - `test_dns_missing_tools`.
- [ ] **Paso 2:** correr `python3 -m unittest tests.test_awscli -v`. Esperado: FAIL.
- [ ] **Paso 3:** implementar `awscli.py` y `tests/helpers.py`, y reemplazar el stub en `catalog.py`.
- [ ] **Paso 4:** correr `python3 -m unittest discover -s tests -v`. Esperado: todo OK.
- [ ] **Paso 5:** hacer commit con `feat: read-only aws cli runner with allowlist and denylist`.

---

### Tarea 4: inventario y motor de `collect.py`

**Archivos:**
- Crear: `scripts/paths.py`, `scripts/collect.py`, `scripts/evaluators.py` (solo el registro y un
  evaluador de ejemplo)
- Crear: `references/inventory.json`
- Prueba: `tests/test_paths.py`, `tests/test_collect.py`, `tests/fixtures/aws/core/*.json`,
  `tests/fixtures/scope-full.json`, `tests/fixtures/scope-resource.json`,
  `tests/fixtures/catalog-engine/engine.json` (4 chequeos sintéticos: jmespath de cuenta, jmespath de
  recurso con `for_each`, python, y uno con `not_enabled_means: fail`)

**Interfaces:**
- **Consume:** `awscli.run_aws`, `awscli.run_dns`, `catalog.load_checks` y `catalog.resolve_mappings`.
- **Produce, en `paths.py`:** `extract(data: object, path: str) -> list`.
  - Mini-lenguaje: claves separadas por `.`; `[]` aplana una lista; `[*]` es sinónimo de `[]`.
  - Una ruta inexistente devuelve `[]`.
  - Ejemplo: `extract({"Buckets":[{"Name":"a"}]}, "Buckets[].Name") == ["a"]`.
- **Produce `inventory.json`:**
  ```
  {"<tipo>": {"service", "operation", "args", "region": "global|each",
              "items_path", "id_path", "name_path", "tags_path", "arn_path"}}
  ```
  Las `*_path` se resuelven con `paths.extract`, relativas a cada ítem. Tipos mínimos: `ec2_instance`,
  `ebs_volume`, `security_group`, `nacl`, `vpc`, `subnet`, `rds_instance`, `rds_cluster`, `s3_bucket`,
  `dynamodb_table`, `efs`, `elbv2`, `asg`, `launch_template`, `lambda_function`, `sqs_queue`,
  `sns_topic`, `kms_key`, `log_group`, `cloudtrail_trail`, `iam_user`, `iam_role`, `eks_cluster`,
  `elasticache_group`, `ses_identity`, `wafv2_web_acl`, `acm_certificate` y `secret` (este último solo
  vía `secretsmanager list-secrets`, sin valores).
- **Produce `scope.json`** (lo escribe Claude o el fixture):
  ```
  {"platform": str, "mode": "full|feature|resource", "target": str|null,
   "regions": [str] | "auto", "profile": str|null,
   "resources": [{"type", "id", "region"}],       // vacío en full
   "domains": [str] | null}                       // null = todos
  ```
- **Produce, en `evaluators.py`:**
  - `EVALUATORS: dict[str, Callable[[dict[str, list[tuple[str, object]]], dict], list[dict]]]`;
  - decorador `@register(name)`.
  - Firma de cada evaluador: `fn(responses, params) -> offenders`.
    - `responses[call_name]` = lista de `(region, data)`.
    - `responses["__inventory__"]` = lista del inventario.
    - Offender = `{"resource_id": str, "region": str, "detail": dict}`.
  - Evaluador de ejemplo: `always_empty`.
- **Produce, en `collect.py`:** `main(argv) -> int` con argumentos
  `--scope FILE --out DIR [--checks-dir DIR] [--inventory FILE]`.
  1. `sts get-caller-identity` → `account_id` e `identity_arn`. Si es `NO_CREDENTIALS`: escribe
     `checks-result.json` con `{"aws": null}` y sale con 2.
  2. Regiones habilitadas: `ec2 describe-regions --filters Name=opt-in-status,Values=opt-in-not-required,opted-in`.
     `scope.regions == "auto"` → regiones habilitadas que tengan algún recurso del inventario, más
     `us-east-1`.
  3. Inventario: por tipo y región, en paralelo con `ThreadPoolExecutor(max_workers=8)` por región. Se
     escribe `inventory.json` como lista de `{"type", "id", "arn", "name", "region", "tags": {k: v}}`.
  4. Selección de chequeos:
     - `mode == full`: todos los de `domains`.
     - `feature/resource`: los de `scope == "resource"` cuyo `resource_types` intersecta los tipos de
       `scope.resources`, más los de `scope == "account"` cuyo `account_context_for` intersecta esos
       tipos.
  5. Ejecución:
     - `region "global"` → `us-east-1`; `"each"` → regiones del alcance, o todas las habilitadas si
       `all_regions`.
     - `for_each` expande una llamada por cada valor extraído.
     - `jmespath` pasa `offenders` como `--query`, y el resultado (una lista) son los ofensores. Las
       expresiones deben proyectar `{resource_id: …, detail: {…}}`. Se documenta en `report-format.md`.
     - `python:<n>` llama a `EVALUATORS[n]`. `claude` no ejecuta evaluación: guarda las respuestas y
       marca `status: "PENDING_CLAUDE"`. `dns` usa `run_dns`.
  6. Estado por chequeo y recurso:

| Situación | Estado |
|---|---|
| Cualquier call `ACCESS_DENIED` | `NO_VERIFICADO`, con `missing: needs` |
| `NOT_ENABLED` y `not_enabled_means == "fail"` | `FAIL`, con `detail.reason = "servicio no habilitado"` |
| `NOT_ENABLED` en otro caso | `NO_VERIFICADO` |
| Sin recursos de `resource_types` en el alcance | `N/A`, con `vacuous: true` |
| Hay ofensores | un `FAIL` por ofensor |
| Sin ofensores | un `PASS` con `resource_id` = `"account"` o la lista de IDs evaluados |

     - En modo feature/resource, los ofensores y los PASS de chequeos `resource` se filtran a los IDs de
       `scope.resources`.
  7. Escribe `raw/<check_id>/<call>-<region>[-<n>].json`, `checks-result.json` e `inventory.json`.
     - `checks-result.json` = `{"aws": {"account_id", "identity_arn", "regions": [...],
       "enabled_regions": [...]}, "results": [{"check_id", "status", "resource_id", "region", "detail",
       "missing", "vacuous"}], "warnings": [str]}`.
     - Permisos amplios: si la identidad tiene `AdministratorAccess` adjunto (verificado con
       `iam list-attached-role-policies` o `list-attached-user-policies` sobre la identidad), se agrega un
       warning. Un `AccessDenied` aquí se ignora.
  8. stdout: resumen de ≤ 40 líneas con conteos por estado, top 10 de `FAIL` por severidad, cantidad de
     `NO_VERIFICADO` y la ruta del directorio.

- [ ] **Paso 1: escribir las pruebas que fallan:**
  - `test_paths.py`: `test_flatten`, `test_missing_key_returns_empty`, `test_nested_lists`,
    `test_star_alias`;
  - `test_collect.py`, todas con `FakeRunner` y el catálogo `catalog-engine`:
    - `test_full_mode_runs_account_and_resource_checks`;
    - `test_resource_mode_filters_to_scope_ids`;
    - `test_feature_mode_includes_account_context_checks`;
    - `test_access_denied_is_not_verified`;
    - `test_not_enabled_means_fail_when_declared`;
    - `test_no_resources_is_vacuous_na`;
    - `test_for_each_expands_calls`;
    - `test_all_regions_flag_uses_enabled_regions`;
    - `test_no_credentials_exits_2`;
    - `test_raw_outputs_written`;
    - `test_stdout_summary_is_bounded`: 300 ofensores, ≤ 40 líneas;
    - `test_admin_identity_warning`;
    - `test_claude_evaluator_marks_pending`;
    - `test_inventory_available_to_evaluators`.
- [ ] **Paso 2:** correr. Esperado: FAIL.
- [ ] **Paso 3:** implementar `paths.py`, `inventory.json`, `evaluators.py` (registro) y `collect.py`.
- [ ] **Paso 4:** correr `python3 -m unittest discover -s tests -v`. Esperado: todo OK.
- [ ] **Paso 5:** hacer commit con `feat: inventory and read-only check collection engine`.

---

## Tareas 5 a 11: catálogo por dominio

**Patrón común a cada tarea de dominio:**

**Archivos:**
- Crear: `references/checks/<dominio>.json`
- Modificar: `scripts/evaluators.py` (agregar los evaluadores del dominio)
- Prueba: `tests/test_eval_<dominio>.py`, `tests/fixtures/aws/<dominio>/*.json`

**Contenido de cada chequeo:**
- llamadas reales de AWS CLI v2;
- `pass_when_text` en castellano;
- `needs` con las acciones IAM;
- mapeos según la tabla de la tarea;
- `remediation.commands` para CloudShell siguiendo las Restricciones globales. Cada comando de remediación
  lleva su variante de verificación en `verify_after`.

**Fuentes del contenido:**
- umbrales, nombres de tests y URLs: `docs/research/vanta-drata-tests.md` (§1, §2 y §3) y
  `soc2-reference-infrastructures.md`;
- TSC e ISO inferidos de los chequeos sin Drata ✓: `vanta-drata-tests.md` §5 y `frameworks-aws-mapping.md`
  §4.3.

**Pasos de cada tarea de dominio:**
- [ ] **Paso 1: escribir las pruebas que fallan** del dominio. Por cada evaluador `python:` hay dos
  pruebas, con un fixture que pasa y otro que falla:
  - `test_<evaluador>_pass`;
  - `test_<evaluador>_fail_reports_offenders`, que verifica el `resource_id` exacto del fixture.

  Además, `test_<dominio>_catalog_valid` corre `catalog.validate` solo sobre ese archivo y espera `[]`.
- [ ] **Paso 2:** correr `python3 -m unittest tests.test_eval_<dominio> -v`. Esperado: FAIL.
- [ ] **Paso 3:** escribir el JSON del dominio y los evaluadores.
- [ ] **Paso 4:** correr el dominio y `python3 auditing-infra-compliance/scripts/validate_catalog.py`.
  Esperado: OK, sin errores.
- [ ] **Paso 5:** hacer commit con `feat: <dominio> checks`.

**Leyenda de las tablas de chequeos:**
- **Eval:** `jq` = jmespath con `--query`; `py:<n>` = evaluador python; `cl` = Claude; `dns`.
- **Rem:** `cli` | `dec` (cli_with_decision) | `plan` (planned_change) | `con` (console_only).
- **Drata:** número de test; con ✓ si está en `drata-dcf.json` (mapeo autoritativo).
- **Vanta:** número de la tabla CIS de `vanta-drata-tests.md` §2.1, o nombre corto.

### Tarea 5: dominio IAM (`iam.json`)

| ID | Chequeo | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| IAM-001 | MFA en root | jq `get-account-summary` | critical | con | 214 ✓ | #2 | IAM.9 / 1.4 |
| IAM-002 | MFA de hardware en root | py:`root_hardware_mfa` (`list-virtual-mfa-devices` + summary) | high | con | 225 ✓ | — | IAM.6 / 1.5 |
| IAM-003 | Root sin access keys | jq (`AccountAccessKeysPresent`) | critical | con | — | #1 | IAM.4 / 1.3 |
| IAM-004 | Root sin uso: 2+ `ConsoleLogin` de root en 7 días = falla | py:`root_usage` (`cloudtrail lookup-events`, `params.days=7`, `params.max=1`) | high | con | 124 ✓ | — | — |
| IAM-005 | MFA en usuarios con consola | py:`cred_report_console_mfa` | high | con | 88 ✓ | #5 | IAM.5 / 1.9 |
| IAM-006 | Contraseña ≥ 14 | jq `get-account-password-policy` | high | cli | 215 ✓ | #3 | IAM.15 / 1.7 |
| IAM-007 | Reuso de contraseñas = 24 | jq | high | cli | 216 ✓ | #4 | IAM.16 / 1.8 |
| IAM-008 | Access keys ≤ 90 días | py:`cred_report_key_age` (`params.max_days=90`) | high | plan | 232 ✓ | #8 | IAM.3 / 1.13 |
| IAM-009 | Credenciales sin uso ≤ 45 días | py:`cred_report_unused` (`params.max_days=45`) | high | cli | 229 | #6 | IAM.22 / 1.11 |
| IAM-010 | ≤ 1 access key activa por usuario | py:`cred_report_multi_keys` | medium | plan | — | #7 | — |
| IAM-011 | Permisos solo vía grupos | py:`user_direct_policies` | high | plan | 217 ✓ | #9 | IAM.2 / 1.14 |
| IAM-012 | Sin políticas propias `*:*` adjuntas | py:`admin_policies` | high | plan | 230 ✓ | #10 | IAM.1 |
| IAM-013 | Wildcards amplios en políticas propias (revisión) | cl | medium | plan | 230 ✓ | — | — |
| IAM-014 | Rol con `AWSSupportAccess` | jq `list-entities-for-policy` | low | dec | — | #11 | IAM.18 / 1.16 |
| IAM-015 | Access Analyzer en todas las regiones (`all_regions`) | jq `accessanalyzer list-analyzers` | high | cli | — | #14 | IAM.28 / 1.19 |
| IAM-016 | Contacto alternativo SECURITY | jq `account get-alternate-contact`; `ResourceNotFound` = falla | low | dec | — | — | Account.1 |
| IAM-017 | Usuarios IAM humanos en lugar de Identity Center (informativo) | py:`iam_human_users` | low | plan | — | — | — |

**Notas de la tarea:**
- **Credential report:** los evaluadores `cred_report_*` comparten la llamada
  `iam generate-credential-report` seguida de `iam get-credential-report`. El campo `Content` viene en
  base64 CSV: se decodifica con `base64` y `csv` de la stdlib.
- **Root, IAM-001 y IAM-003:** la remediación es `console_only` con pasos de consola numerados; CLI no puede
  habilitar MFA de root.
- **Contraseñas, IAM-006 e IAM-007:** un único comando `update-account-password-policy` con el set
  completo:

  ```
  --minimum-password-length 14 --password-reuse-prevention 24 --require-symbols
  --require-numbers --require-uppercase-characters --require-lowercase-characters
  --allow-users-to-change-password
  ```

  `notes` advierte que reemplaza la política entera.

### Tarea 6: dominio logging (`logging.json`)

| ID | Chequeo | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| LOG-001 | Trail multi-región existe e `IsLogging=true` | py:`cloudtrail_active` (`describe-trails` + `get-trail-status` for_each) | high | dec | — | #25 | CloudTrail.1 / 3.1 |
| LOG-002 | Validación de archivos de log | jq `describe-trails` | high | cli | 205 ✓ | #26 | CloudTrail.4 / 3.2 |
| LOG-003 | Trail cifrado con CMK (`KmsKeyId` presente) | jq | high | plan | 222 ✓ | #28 | CloudTrail.2 / 3.5 |
| LOG-004 | Data events de S3, lectura y escritura | py:`trail_s3_data_events` (`get-event-selectors` for_each) | high | dec | 226 ✓ | #17, #18 | S3.22 / S3.23 |
| LOG-005 | Access logging en el bucket de CloudTrail | py:`trail_bucket_logging` (`s3api get-bucket-logging`) | high | dec | 221 ✓ | #19 | CloudTrail.7 / 3.4 |
| LOG-006 | Bucket de CloudTrail: versionado y política con `aws:SourceArn` | py:`trail_bucket_hardening` | medium | dec | — | — | — |
| LOG-007 | CloudTrail → CloudWatch Logs con metric filters CIS (root, IAM, no autorizadas) | py:`trail_cw_metric_filters` | medium | plan | — | — | CloudWatch.1–.14 (CIS 1.4) |
| LOG-008 | Flow Logs en todas las VPC de todas las regiones (`all_regions`, `resource_types: [vpc]`) | py:`vpc_flow_logs` | high | dec | 224 ✓ | #30 | EC2.6 / 3.7 |
| LOG-009 | Retención de log groups ≥ 365 días (sin retención = pasa) | jq `logs describe-log-groups` | high | cli | 111 | "AWS Server Logs" | — |
| LOG-010 | Buckets de logs: lifecycle no expira antes de 365 días | py:`log_bucket_lifecycle` | medium | dec | — | — | — |
| LOG-011 | Access logs del ALB | py:`alb_access_logs` (`describe-load-balancer-attributes` for_each) | medium | dec | — | — | ELB.5 |
| LOG-012 | Logging del WAF | py:`waf_logging` (`wafv2 get-logging-configuration` for_each) | medium | dec | — | — | WAF.11 |
| LOG-013 | Audit logs de EKS | jq `eks describe-cluster` for_each | high | cli | 310 ✓ | — | EKS.8 |

**Notas de la tarea:**
- **Retención (LOG-009):** el comando es `aws logs put-retention-policy --log-group-name "{resource_id}"
  --retention-in-days 365`. `notes` advierte el costo.
- **Bucket de logs (LOG-010):** se identifica como el destino de trails y access logs, o por tag/nombre
  que contenga `log`.

### Tarea 7: dominios detection y compute (`detection.json`, `compute.json`)

| ID | Chequeo | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| DET-001 | GuardDuty activo en cada región con recursos (`all_regions`; región sin recursos sin detector = `low`, vía `detail.severity_override`) | py:`guardduty_regions` | high | cli | 105 ✓ | — | GuardDuty.1 |
| DET-002 | GuardDuty S3 Protection | py:`guardduty_s3_protection` (`get-detector`) | high | cli | 105 ✓ | — | — |
| DET-003 | Regla de EventBridge para findings de GuardDuty con destino | py:`guardduty_eventbridge` (`events list-rules` + `list-targets-by-rule`) | medium | dec | — | — | — |
| DET-004 | Security Hub habilitado con FSBP o CIS (`not_enabled_means: fail`) | py:`securityhub_standards` | high | cli | — | #31 | — |
| DET-005 | AWS Config en todas las regiones: grabando, todos los tipos, IAM diario, delivery channel | py:`config_recorder` (`describe-configuration-recorders` + `...-status` + `describe-delivery-channels`) | high | dec | — | #27, "Config enabled correctly" | Config.1 / 3.3 |
| DET-006 | Inspector activo para EC2, ECR y Lambda (`not_enabled_means: fail`) | py:`inspector_status` (`inspector2 batch-get-account-status`) | high | cli | 21 | "Critical vulnerabilities… (Inspector)" | Inspector.1–.4 |
| DET-007 | Sin findings CRITICAL ni HIGH abiertos en Inspector | jq `inspector2 list-findings --filter-criteria …` | high | plan | 21 | ídem | — |
| CMP-001 | IMDSv2 obligatorio en instancias | jq `ec2 describe-instances` | high | cli | 292 ✓ | #36 | EC2.8 / 5.7 |
| CMP-002 | Launch templates de ASG con IMDSv2 | py:`lt_imdsv2` | high | plan | 292 ✓ | "IMDSv1 disabled (ASG)" | — |
| CMP-003 | Instancias con instance profile | jq | medium | dec | — | #12 | — |
| CMP-004 | LB en ≥ 2 AZ en regiones con EC2 | py:`lb_multi_az` | high | plan | 130 ✓ | — | ELB.10/.13 |
| CMP-005 | Cómputo en ASG | py:`asg_present` | high | plan | 131 ✓ | — | — |
| CMP-006 | Instancias gestionadas por SSM, con asociación de parches | py:`ssm_managed` (`ssm describe-instance-information` + `describe-instance-patch-states`) | medium | plan | — | — | SSM.1 |

**Notas de la tarea:**
- **Remediación de DET-001:** se genera un comando por región ofensora.

  ```
  aws guardduty create-detector --enable --region "{region}" --features '[{"Name":"S3_DATA_EVENTS","Status":"ENABLED"}]'
  ```
- **Remediación de CMP-002:** pasos para crear una nueva versión del launch template con
  `MetadataOptions.HttpTokens=required`, ponerla por defecto y hacer `start-instance-refresh`. `notes`
  advierte que reemplaza las instancias.

### Tarea 8: dominio encryption, en reposo y en tránsito (`encryption.json`)

| ID | Chequeo | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| ENC-001 | Cifrado EBS por defecto en cada región con EC2 | jq `ec2 get-ebs-encryption-by-default` | high | cli | 218 ✓ | #20 | EC2.7 / 5.1.1 |
| ENC-002 | Volúmenes EBS cifrados | jq `describe-volumes` | high | plan | 218 ✓ | — | EC2.3 |
| ENC-003 | RDS (instancias y clusters) cifrados | jq | high | plan | 68 ✓ | #21 | RDS.3 / 2.2.1 |
| ENC-004 | EFS cifrado | jq | high | plan | 231 ✓ | #24 | EFS.1 |
| ENC-005 | Cifrado por defecto en S3 | py:`s3_default_encryption` | high | cli | 69 ✓ | — | — |
| ENC-006 | Rotación de CMK propias simétricas | py:`kms_rotation` (`list-keys` + `describe-key` + `get-key-rotation-status`) | high | cli | 223 ✓ | #29 | KMS.4 / 3.6 |
| ENC-007 | CMK no programadas para borrado | jq `describe-key` for_each | medium | dec | — | — | KMS.3 |
| ENC-008 | Rotación habilitada en Secrets Manager | jq `secretsmanager list-secrets` | medium | dec | — | — | SecretsManager.1 |
| TLS-001 | Buckets S3 niegan `aws:SecureTransport=false` | py:`s3_tls_only` (`get-bucket-policy` for_each; `NoSuchBucketPolicy` = falla) | high | dec | 234 ✓ | #15 | S3.5 / 2.1.1 |
| TLS-002 | Listeners HTTP del ALB redirigen a HTTPS | py:`alb_http_redirect` | high | cli | 299 ✓ | — | ELB.1 |
| TLS-003 | Política TLS del ALB ≥ 1.2 (`ELBSecurityPolicy-TLS13-1-2-2021-06` recomendada) | py:`alb_tls_policy` | medium | cli | — | — | ELB.17 |
| TLS-004 | RDS fuerza SSL (`rds.force_ssl=1` / `require_secure_transport=ON`) | py:`rds_force_ssl` | medium | plan | — | — | — |
| TLS-005 | Certificados ACM con > 30 días de vigencia | py:`acm_expiry` (`params.min_days=30`) | medium | plan | — | #13 (certs IAM) | ACM.1 |

**Notas de la tarea:**
- **ENC-003:** `planned_change` con los pasos snapshot → `copy-db-snapshot --kms-key-id` → restore →
  cambio de endpoint. `downtime: true`.
- **TLS-001:** el comando trae la política actual a un archivo, agrega el statement Deny con
  `python3 -c` (CloudShell tiene python3) y hace `put-bucket-policy`. `kind: cli_with_decision`, porque hay
  que revisar la política resultante antes de aplicarla.
- **TLS-004:** sin control de Security Hub verificado; usa solo `tsc_inferred` CC6.7 e `iso_inferred`
  A.8.24.

### Tarea 9: dominios network y data (`network.json`, `data.json`)

| ID | Chequeo | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| NET-001 | Sin 0.0.0.0/0 ni ::/0 a 22 en SG de regiones con ENIs activas | py:`sg_open_port` (`params.port=22`) | high | cli | 102 ✓ | #33, #34 | EC2.53/.54 |
| NET-002 | Ídem para 3389 | py:`sg_open_port` (`port=3389`) | high | cli | 228 ✓ | #33, #34 | EC2.53/.54 |
| NET-003 | Ídem para 80 | py:`sg_open_port` (`port=80`) | high | dec | 291 ✓ | — | — |
| NET-004 | Sin regla "ALL traffic" desde CIDR | py:`sg_all_traffic` | high | cli | 119 ✓ | — | — |
| NET-005 | NACL sin 0.0.0.0/0 ni ::/0 a 22/3389 | py:`nacl_admin_ports` | high | dec | 227 ✓ | #32 | EC2.21 |
| NET-006 | SG por defecto sin reglas, en todas las VPC de todas las regiones (`all_regions`) | py:`default_sg_empty` | high | cli | 233 ✓ | #35 | EC2.2 / 5.5 |
| NET-007 | RDS no público ni en subnet con ruta a IGW | py:`rds_not_public` (`describe-db-instances` + `describe-route-tables`) | critical | plan | 220 ✓ | #23 | RDS.2 |
| NET-008 | WAF asociado a ALB, API GW y CloudFront públicos | py:`waf_associated` (`wafv2 list-resources-for-web-acl`) | high | dec | 122 ✓ | — | — |
| DAT-001 | Backups automáticos de RDS: retención > 0 (FAIL); < 7 → ofensor con `severity_override: low` | py:`rds_backups` | high | cli | 107 ✓ | — | RDS.11 |
| DAT-002 | RDS Multi-AZ en prod (tag `Environment` en {prod, production}, o sin tag) | jq | high | plan | 30 ✓ | — | RDS.5 |
| DAT-003 | RDS con auto minor upgrade | jq | high | cli | 219 ✓ | #22 | RDS.13 |
| DAT-004 | RDS con deletion protection | jq | medium | cli | — | — | RDS.8 |
| DAT-005 | DynamoDB PITR | jq `describe-continuous-backups` for_each | high | cli | 301 ✓ | — | DynamoDB.2 |
| DAT-006 | Versionado S3 | jq `get-bucket-versioning` for_each | high | cli | 108 ✓ | — | — |
| DAT-007 | Block Public Access por bucket (los 4 flags) | py:`s3_bpa` | critical | cli | 104 ✓ | #16 | S3.8 |
| DAT-008 | Jobs de AWS Backup del día anterior OK | py:`backup_jobs_recent` | high | plan | 132 ✓ | — | — |
| DAT-009 | Alertas de fallo de backup (notificaciones del vault a SNS) | py:`backup_vault_notifications` | high | dec | 133 ✓ | — | — |
| DAT-010 | Plan de AWS Backup con regla diaria y retención ≥ 7 | py:`backup_plan_rules` | medium | dec | — | — | — |
| DAT-011 | ElastiCache Multi-AZ | jq | high | plan | 30 ✓ | — | ElastiCache.3 |

**Notas de la tarea:**
- **NET-003 (puerto 80):** `notes` explica que un ALB con redirect sigue fallando el test 291 de Drata. La
  opción es exponer solo 443, o excluir el recurso en Drata con justificación.
- **Severidad:** `severity_override` en `detail` se respeta en la Tarea 13.

### Tarea 10: dominio monitoring (`monitoring.json`)

Todos usan `py:alarm_coverage` con `params = {"namespace", "metric", "resource_dimension"}`.

**Lógica de `alarm_coverage`:**
1. Por cada recurso del tipo, existe una alarma (`cloudwatch describe-alarms`) con esa métrica y esa
   dimensión.
2. Esa alarma tiene `AlarmActions` hacia un topic SNS.
3. Ese topic tiene ≥ 1 suscripción confirmada: `sns list-subscriptions-by-topic`, con `SubscriptionArn`
   distinto de `PendingConfirmation`.

`detail.missing_part` dice cuál de las tres partes falta: `alarm`, `action` o `confirmed_subscription`.

| ID | Recurso | Métrica | Sev | Drata | Vanta |
|---|---|---|---|---|---|
| MON-001 | RDS | `AWS/RDS CPUUtilization` | high | 112 ✓ | Tests de alarmas |
| MON-002 | RDS | `FreeStorageSpace` | high | 113 ✓ | ídem |
| MON-003 | RDS | `ReadIOPS` / `WriteIOPS` (2 offenders posibles) | high | 114 ✓, 290 ✓ | ídem |
| MON-004 | RDS | `FreeableMemory` | high | 206 ✓ | ídem |
| MON-005 | EC2/ASG | `AWS/EC2 CPUUtilization` (dimensión `InstanceId` o `AutoScalingGroupName`) | high | 118 ✓ | ídem |
| MON-006 | ALB | `HTTPCode_Target_5XX_Count`, `UnHealthyHostCount` y `TargetResponseTime` | high | 296 ✓, 298 ✓, 294 ✓ | ídem |
| MON-007 | SQS | `ApproximateAgeOfOldestMessage` | high | 115 ✓ | ídem |
| MON-008 | Lambda | `Errors` | high | 300 ✓ | ídem |
| MON-009 | DynamoDB/ElastiCache | storage o CPU según tipo | high | 117 ✓ | ídem |

**Remediación:** todos los chequeos usan `cli_with_decision`. El comando es `put-metric-alarm`, con el
umbral como placeholder `__COMPLETAR_UMBRAL__` y `--alarm-actions` con `__COMPLETAR_SNS_TOPIC_ARN__`, más
el paso de suscribir y confirmar el email.

### Tarea 11: dominios inventory, integration y email (`inventory.json` en checks, `integration.json`, `email.json`)

| ID | Chequeo | Eval | Sev | Rem | Drata | Vanta |
|---|---|---|---|---|---|---|
| INV-001 | Tag `VantaOwner` con formato email en recursos de tipos soportados por Vanta | py:`tag_present` (`params.key=VantaOwner`, `params.pattern=email`) sobre `__inventory__` | high | dec | — | "Inventory items have active owners" |
| INV-002 | `VantaContainsUserData` en S3, RDS, DynamoDB y SQS | py:`tag_present` | medium | dec | — | "…contain user data" |
| INV-003 | `VantaNonProd=true` no está en recursos con `Environment` prod | py:`nonprod_on_prod` | high | cli | — | (scoping) |
| INV-004 | Tags organizacionales configurables (`params.keys`, por defecto `Project`, `Environment`, `Owner`) | py:`tags_present` | low | dec | — | — |
| INT-001 | Si existe `DrataAutopilotRole`: tiene `SecurityAudit`; si no existe → `N/A` | py:`drata_role` | high | cli | 123 ✓ | — |
| INT-002 | `DrataAutopilotRole` con `backup:ListRecoveryPointsByResource` y `backup:ListBackupJobs` | py:`drata_backup_perms` | medium | cli | 132 ✓, 133 ✓ | — |
| INT-003 | Si existe `vanta-auditor`: `SecurityAudit` + `VantaAdditionalPermissions` administrada (no inline) | py:`vanta_role` | high | dec | — | doc. de permisos |
| INT-004 | Key policies de CMK permiten a los roles auditores las acciones de lectura | py:`kms_auditor_access` | medium | dec | 223 ✓ | KMS doc |
| EML-001 | Identidad SES verificada con Easy DKIM `SUCCESS` | jq `sesv2 get-email-identity` for_each | medium | dec | — | — |
| EML-002 | Configuration set con `TlsPolicy=REQUIRE` | jq `sesv2 get-configuration-set` | medium | cli | — | — |
| EML-003 | Configuration set con event destination | jq `get-configuration-set-event-destinations` | medium | dec | — | — |
| EML-004 | SPF en el dominio de envío | dns TXT (`v=spf1`) | medium | dec | — | — |
| EML-005 | DMARC `_dmarc.<dominio>` con `p=quarantine` o `reject` (ausente → `high`) | dns TXT | high | dec | — | — |
| EML-006 | Cuenta SES con production access y suppression list | jq `sesv2 get-account` | low | con | — | — |

**Notas de la tarea:**
- **Nombre del archivo:** el archivo de chequeos de inventario se llama `checks/inventory.json`, distinto de
  `references/inventory.json` (tipos de recurso). No confundirlos en `load_checks`, que solo lee
  `checks/`.
- **Mapeos:** para EML-*, INV-* y los chequeos sin Drata ✓, completar `tsc_inferred` e `iso_inferred`.
  - INV → CC6.1/A.5.9.
  - EML → CC6.7/A.8.24, A.5.14.
- **Cierre:** al terminar, `validate_catalog.py` imprime `OK: 98 checks` (17 + 13 + 13 + 13 + 19 + 9 + 14).

---

### Tarea 12: índice del vault y resolución de feature

**Archivos:**
- Crear: `auditing-infra-compliance/scripts/vault_index.py`
- Crear: `auditing-infra-compliance/scripts/redact.py` (mínimo: `mask(text) -> str` para claves
  `AKIA`/`ASIA` y asignaciones `aws_secret_access_key`)
- Crear: `tests/fixtures/typed-vault/`
  - estructura de `creating-typed-knowledge-vaults`: `_meta/relations.md`, `_meta/edges.md`,
    `systems/`, `constraints/`, `decisions/`, `failures/`, `MOC/`;
  - plataforma ficticia "Acme Notes" con la feature `systems/Email delivery.md`, que `depends on` →
    SES Identity, Mailer Lambda y Mail Queue (SQS);
  - `Mailer Lambda` `depends on` → `Mailer Role`;
  - un `constraints/` de PII;
  - una nota `status: proposed` (DMARC reject);
  - IDs ficticios dentro de las notas.
- Crear: `tests/fixtures/free-vault/`
  - 6 notas a mano: hub `Acme Notes.md` con `## Conectado a`, `RDS - acme-db.md` con una tabla
    `| Campo | Valor |` que afirma "KMS: CMK propia", `S3 - uploads.md`, `VPC.md`;
  - una nota con un link roto.
  - La nota con secreto **no** se commitea: las pruebas la crean con `helpers.make_secret_note` en una
    copia temporal.
- Prueba: `tests/test_vault_index.py`

**Interfaces:**
- **Produce `vault_index.py`:**
  - `build_index(vault: Path) -> dict`;
  - `resolve_feature(index: dict, query: str, max_depth: int = 3) -> dict`;
  - CLI:
    - `vault_index.py index <vault> -o vault-index.json`;
    - `vault_index.py feature <vault-index.json> "<texto>"` → JSON por stdout.
- **Formato del índice:**
  ```
  {"kind": "typed|free", "root": str,
   "notes": [{"path", "title", "type"|null, "status"|null, "source": [str],
              "edges": [{"relation", "target", "layer": "structural|associative"}],
              "links": [str], "aws_ids": [{"kind", "value"}],
              "kv": {campo: valor}, "headings": [str], "inferred_type": str|null}],
   "broken_links": [{"from", "target"}],
   "secrets_detected": [{"path", "pattern"}],
   "obsidian_plugins": [str]}
  ```
- **Detección del tipo de vault:** es `typed` si existe `_meta/relations.md`, o si ≥ 50 % de las notas
  tienen frontmatter `type:`.
- **Lectura de las notas:**
  - El frontmatter se parsea a mano: bloque `---` con `clave: valor` y listas `- item`. Sin PyYAML.
  - Aristas: regex `^- (?P<rel>[a-z ]+) → \[\[(?P<target>[^\]|#]+)`.
  - `aws_ids`, con estas regex:
    - `arn:aws[a-z-]*:[^\s)\]|]+`;
    - `\b(i|sg|vpc|subnet|vol|acl|rtb|igw|nat|eni|lt)-[0-9a-f]{8,17}\b`;
    - `\bdb-[A-Z0-9]{26}\b`.
  - Claves de acceso: el patrón `(AKIA|ASIA)[0-9A-Z]{16}` va **solo** a `secrets_detected` (`pattern:
    "aws_access_key_id"`), nunca a `aws_ids`.
  - `inferred_type` (vault libre): prefijo del nombre de archivo antes de ` - ` o primer token, mapeado a
    un tipo de `inventory.json`: `RDS`→`rds_instance`, `S3`→`s3_bucket`, `VPC`→`vpc`, `ALB`→`elbv2`,
    `EC2`→`ec2_instance`, `SES`→`ses_identity`, `Lambda`→`lambda_function`, `SQS`→`sqs_queue`,
    `IAM`→`iam_role`, `KMS`→`kms_key`.
- **Contenido de las notas:** todo texto que entra al índice (`kv`, `title`, `headings`) pasa por
  `redact.mask`.
- **Archivos que se leen:** solo `*.md`. Se omiten dotfiles y dotdirs; `.obsidian/plugins` solo se lista.
- **Respuesta de `resolve_feature`:**
  ```
  {"candidates": [path, …],
   "chosen": path|null,
   "components": [{"path", "title", "via": [relaciones], "depth", "aws_ids", "status"}],
   "constraints": [path], "pii": bool,
   "confidence": "typed|inferred"}
  ```
- **Lógica de `resolve_feature`:**
  - **Candidatas:** coincidencia exacta de título (sin mayúsculas ni acentos), luego coincidencia en H1,
    luego en el cuerpo.
  - **Varias candidatas:** si hay > 1 candidata del mismo nivel, `chosen = null` (Claude pregunta).
  - **Vault tipado:** BFS por aristas estructurales salientes `depends on`, `requires` y `enables`, más
    entrantes `is part of` (vía `_meta/edges.md` o por escaneo). Solo se recolectan notas en `systems/`;
    las de `constraints/` alcanzadas van a `constraints`.
  - **Vault libre:** BFS de wikilinks, con profundidad 2.
  - **PII:** `pii` es true si un constraint o un componente contiene `PII`, `datos personales`,
    `user data`, `personal data` o `email`.

- [ ] **Paso 1: escribir las pruebas que fallan:**
  - `test_detects_typed`, `test_detects_free`;
  - `test_parses_frontmatter_and_edges`;
  - `test_extracts_aws_ids`;
  - `test_masks_keys_in_index`: copia temporal del vault libre más `make_secret_note`. La clave armada no
    aparece en el JSON serializado del índice, y `secrets_detected` contiene el path;
  - `test_ignores_dotfiles_and_env`: crear `.env` en una copia temporal del fixture; no se lee (se usa un
    mock de `open` que falla si se abre);
  - `test_broken_links_reported`;
  - `test_feature_typed_email_components`: componentes = {SES Identity, Mailer Lambda, Mail Queue, Mailer
    Role}; `pii` es True; la nota `proposed` aparece con `status == "proposed"`;
  - `test_feature_ambiguous_returns_candidates`;
  - `test_feature_not_found_empty`;
  - `test_free_vault_inferred_types_and_kv`: `kv` de RDS incluye la afirmación de la CMK.
- [ ] **Paso 2:** correr. Esperado: FAIL.
- [ ] **Paso 3:** implementar `vault_index.py` y el `redact.py` mínimo.
- [ ] **Paso 4:** correr todo. Esperado: OK.
- [ ] **Paso 5:** hacer commit con `feat: vault indexer and feature resolution`.

---

### Tarea 13: enmascarado y armado de `findings.json`

**Archivos:**
- Modificar: `auditing-infra-compliance/scripts/redact.py`
- Crear: `auditing-infra-compliance/scripts/assemble_findings.py`
- Crear: `tests/fixtures/vault-claims.json`, `tests/fixtures/run-sample/` (salida de `collect` con
  `checks-result.json` e `inventory.json` ficticios)
- Prueba: `tests/test_redact.py`, `tests/test_assemble.py`

**Interfaces:**
- **Consume:** `catalog.load_checks`, `catalog.resolve_mappings` y `catalog.load_frameworks`, además de
  `checks-result.json` e `inventory.json` (Tarea 4) y `vault-index.json` (Tarea 12).
- **Produce, en `redact.py`:**
  - `mask(text: str, *, keep_emails: frozenset[str] = frozenset()) -> str`;
  - `mask_obj(obj: object, **kw) -> object` (recursivo).
- **Produce `vault-claims.json`** (lo escribe Claude):
  ```
  [{"kind": "DRIFT|UNDOCUMENTED|DOCUMENTED_ONLY|DOCUMENTED_GAP|EVAL",
    "check_id": str|null, "resource": {"type","id","region"}|null,
    "vault_note": str|null, "vault_claim": str|null, "actual": str|null,
    "status": str|null, "detail": obj|null,      // solo para EVAL (resuelve un PENDING_CLAUDE)
    "severity": str|null,                         // obligatorio si check_id es null
    "breaks_tests": [{"tool","test"}]}]           // para recomendaciones del vault que romperían tests
  ```
- **Produce, en `assemble_findings.py`:**
  - CLI: `--run-dir DIR [--vault-index FILE] [--vault-claims FILE] --platform STR --mode STR [--target STR] [--lang es]`.
    Escribe `DIR/findings.json`.
  - Función: `assemble(run_dir: Path, vault_index: dict|None, claims: list, meta: dict, skill_dir: Path) -> dict`.
- **Esquema de `findings.json`:**
  ```
  {"meta": {"platform", "mode", "target", "generated_at" (ISO 8601 local), "lang",
            "catalog_checks": int, "vault": {"path", "kind"}|null,
            "aws": {"account_id", "identity_arn", "regions"}|null},
   "summary": {"by_status": {…}, "by_severity_fail": {…}, "drata_tests_failing": [int],
               "vanta_tests_failing": [str], "not_verified": int},
   "findings": [{"id": "F-0001", "check_id", "title", "domain", "status", "severity",
                 "resource": {"type","id","region","name"}, "evidence": obj, "vault_claim": str|null,
                 "vault_note": str|null, "mappings": <resolve_mappings>, "remediation": {…instanciada},
                 "evaluated_by": "script|claude", "vacuous": bool, "breaks_tests": [...],
                 "depends_on_me": [{"tool","test","name"}]}],
   "dependencies": [{"resource_id", "resource_type", "tests": [{"tool","test","name"}]}],
   "coverage": {"iso": [{"id","name","status": "FAIL|PASS|NO_VERIFICADO|NOT_TOUCHED","category": "technical|organizational|inherited"}],
                "tsc": [ … igual … ]},
   "warnings": [str], "notes": [str]}
  ```
- **Reglas de `assemble`:**
  1. **Orden de los findings:** severidad (`critical` → `low`), luego estado (`FAIL`, `DRIFT`,
     `UNDOCUMENTED`, `DOCUMENTED_GAP`, `NO_VERIFICADO`, `DOCUMENTED_ONLY`, `PASS`, `N/A`), luego
     `check_id`. Los IDs `F-NNNN` se asignan en ese orden.
  2. **Severidad:** `severity_override` de `detail` gana sobre la del catálogo. Un claim con `breaks_tests`
     no vacío → `DRIFT` con severidad `high`. `UNDOCUMENTED` sin severidad → `low`.
  3. **Remediación:** se reemplazan `{resource_id}`, `{region}`, `{account_id}` y `{resource_name}` en
     `commands`, `steps` y `verify_after`. Los `__COMPLETAR_*__` se dejan intactos.
  4. **Dependencias:** cada `PASS` con mapeos Drata/Vanta agrega sus tests al recurso, deduplicados.
     `depends_on_me` de cada finding es la entrada de `dependencies` de su recurso.
  5. **Cobertura:** el estado de cada ID ISO/TSC es el peor de los findings que lo mapean (`FAIL` >
     `NO_VERIFICADO` > `PASS`). Sin findings: `NOT_TOUCHED`. La `category` sale de `technical` y
     `responsibility` en los JSON de normas: `inherited` gana; si no, `technical` → `technical`; si no,
     `organizational`.
  6. **Enmascarado:** `mask_obj` sobre `evidence`, `vault_claim` y `actual`, con `keep_emails` = valores
     de tags `VantaOwner` del inventario.
  7. **Warnings:** se agregan los de `collect`, los `broken_links` y los `secrets_detected` del vault. Por
     cada secreto detectado se agrega un finding `critical` con `check_id: null`, título "Credenciales en
     texto plano en el vault", y como evidencia solo path y patrón.
  8. **Claims EVAL:** resuelven los `PENDING_CLAUDE` con el mismo `check_id` y recurso. Los
     `PENDING_CLAUDE` sin claim EVAL quedan `NO_VERIFICADO`, con warning. Los findings resueltos por EVAL
     llevan `evaluated_by: "claude"`.
  9. **Sin AWS** (`checks-result.json` con `"aws": null` o ausente): solo hay findings `DOCUMENTED_*`,
     `DRIFT` del vault y secretos detectados. `meta.aws` es null.

- [ ] **Paso 1: escribir las pruebas que fallan:**
  - `test_redact.py`:
    - `test_mask_access_key`: la clave armada `"AKIA" + "TESTKEYABCDEMNOP"` → `AKIA…MNOP`;
    - `test_mask_secret_assignment`;
    - `test_mask_email_except_kept`;
    - `test_mask_obj_recursive`.
  - `test_assemble.py`:
    - `test_sort_order_and_ids`;
    - `test_severity_override`;
    - `test_breaks_tests_claim_is_high_drift`;
    - `test_remediation_placeholders_filled_and_completar_kept`;
    - `test_dependencies_from_passes`;
    - `test_coverage_worst_status_and_categories`: A.7.1 es `inherited` y `NOT_TOUCHED`;
    - `test_findings_are_masked`;
    - `test_secret_in_vault_creates_critical_finding_without_value`;
    - `test_eval_claim_resolves_pending`;
    - `test_pending_claude_unresolved_becomes_not_verified`;
    - `test_no_aws_only_documented_findings`;
    - `test_no_percentage_anywhere`: el JSON serializado no contiene `%` ni las claves `score`/`compliance`.
- [ ] **Paso 2:** correr. Esperado: FAIL.
- [ ] **Paso 3:** implementar.
- [ ] **Paso 4:** correr todo. Esperado: OK.
- [ ] **Paso 5:** hacer commit con `feat: findings assembly with masking, dependencies and coverage`.

---

### Tarea 14: plantilla y renderer HTML

**Archivos:**
- Crear: `auditing-infra-compliance/assets/report-template.html`
- Crear: `auditing-infra-compliance/scripts/render_report.py`
- Crear: `tests/fixtures/findings-sample.json`
  - cubre todos los estados y severidades, un `planned_change` y un nombre hostil
    `"<script>alert(1)</script>"`;
  - incluye un tag `x"onmouseover=` y un comando con backtick.
- Prueba: `tests/test_render.py`

**Interfaces:**
- **Consume:** `findings.json` (Tarea 13).
- **Produce:** `render_report.py <findings.json> -o <report.html>` y la función
  `render(findings: dict, template: str) -> str`.
- **Inyección de datos:** la plantilla contiene un único marcador
  `<script id="data" type="application/json">/*__FINDINGS__*/</script>`. `render` reemplaza el marcador por
  el JSON, escapando `<` como `<`, `>` como `>` y `&` como `&`.
- **El JS de la plantilla renderiza:**
  1. **Encabezado:** plataforma, modo y target, fuentes, cuenta, identidad, regiones y fecha.
  2. **Resumen:** chips de conteo por estado y por severidad (solo `FAIL`), lista de tests de Drata y
     Vanta fallando, conteo de `NO_VERIFICADO`. Sin porcentaje.
  3. **Filtros:** severidad, estado, dominio, herramienta (Drata/Vanta) y norma (SOC 2/ISO), más un
     buscador. El filtro elegido se guarda en `localStorage`, dentro de `try/catch`.
  4. **Tarjetas:**
     - título, recurso y región, estado y severidad;
     - chips de mapeo: los inferidos con estilo punteado y el texto "inferido";
     - evidencia en `<pre>`;
     - lo que afirma el vault;
     - "Tests que dependen de este recurso" (`depends_on_me`);
     - remediación:
       - bloque `<pre><code>` con botón **Copiar** por comando, y botón "Copiar todo" del bloque;
       - etiquetas de riesgo, downtime y tipo;
       - `__COMPLETAR_*__` resaltado con `<mark>`;
       - para `planned_change`, aviso en rojo y pasos numerados;
       - para `console_only`, pasos sin bloque de código;
       - "Verificar después" con su propio Copiar.
  5. **Botón global** "Copiar arreglos de bajo riesgo", por severidad: concatena los `commands` de los
     `FAIL` con `kind == "cli"` y `risk == "low"`, separados por comentarios `# F-NNNN …`.
  6. **"No tocar sin revisar":** tabla de `dependencies`.
  7. **Cobertura:** dos tablas, ISO y TSC, agrupadas por categoría.
  8. **Advertencias y notas.**
  9. **Pie fijo:** "Pre-auditoría técnica automatizada. No es una opinión de auditoría ni cubre controles
     organizacionales (políticas, RRHH, equipos, proveedores, ISMS)."
- **Copy:** `navigator.clipboard.writeText`. Si falla (por ejemplo, desde `file://` sin permisos), usa un
  `textarea` oculto con `document.execCommand('copy')`. La confirmación es visual ("Copiado").
- **Escapado:** todo texto entra al DOM vía `textContent`, nunca `innerHTML` con datos. `<mark>` para
  `__COMPLETAR_*__` se arma partiendo el texto y creando nodos.
- **Tema:** tokens CSS en `:root`, modo oscuro con `@media (prefers-color-scheme: dark)`, `@media print`
  (expande todo y oculta botones y filtros). Layout usable a 375 px de ancho.

- [ ] **Paso 1: escribir las pruebas que fallan:**
  - `test_no_external_resources`: regex sobre el HTML sin `<script[^>]+src=`, `<link[^>]+href=`,
    `<img[^>]+src="http`, `@import` ni `url(http`;
  - `test_data_injected_and_escaped`: el HTML no contiene `</script><script>alert` ni el literal
    `<script>alert(1)`, y contiene `<script`;
  - `test_no_innerhtml_with_data`: regex `innerHTML\s*=\s*[^'"\s]` sobre la plantilla → 0 coincidencias;
  - `test_has_copy_fallback`: la plantilla contiene `navigator.clipboard` y `execCommand('copy')`;
  - `test_footer_disclaimer_present`;
  - `test_no_percentage_in_summary_strings`: las strings de i18n de la plantilla no contienen `%`;
  - `test_hostile_names_escaped`: render del fixture; luego `html.parser` de la stdlib verifica que haya
    exactamente 2 elementos `<script>`, el de datos y el de la app.
- [ ] **Paso 2:** correr. Esperado: FAIL.
- [ ] **Paso 3:** implementar la plantilla y el renderer.
- [ ] **Paso 4:** correr todo. Esperado: OK.
- [ ] **Paso 5: verificación visual.** Renderizar `findings-sample.json` a
  `compliance-reports/sample/report.html` y abrirlo en el navegador. Revisar:
  - copiar un comando y pegarlo en una terminal;
  - modo oscuro;
  - vista de impresión;
  - ancho de 375 px.

  Anotar los problemas y corregirlos antes del commit.
- [ ] **Paso 6:** hacer commit con `feat: self-contained html report with copyable remediation`.

---

### Tarea 15: SKILL.md y referencias, con TDD de skill

**Archivos:**
- Crear: `auditing-infra-compliance/SKILL.md`
- Crear: `auditing-infra-compliance/references/vault-reading.md`, `remediation-guidelines.md`,
  `report-format.md`, `drata-vanta.md`
- Crear: `tests/skill-scenarios.md` (escenarios y resultados de la línea base y del post)

**Interfaces:**
- **Consume:** todas las CLIs de las tareas 2, 4, 12, 13 y 14 (nombres y argumentos exactos de sus
  bloques Interfaces).

**Contenido obligatorio de `SKILL.md`:**
- **Frontmatter:**
  - `name: auditing-infra-compliance`;
  - `description:` en tercera persona, "Use when…". Se dispara con:
    - pedidos de auditoría o pre-auditoría SOC 2 / ISO 27001 de infraestructura AWS;
    - "¿pasa Drata/Vanta?";
    - revisar una feature o un recurso (ID/ARN) contra compliance;
    - en castellano o en inglés.
  - Menos de 1024 caracteres.
- **Cuerpo procedural** (≤ 500 líneas), en este orden:
  1. **Entradas:** una sola pregunta agrupada para lo que falte (sección 4 de la spec).
  2. **Preflight y reglas duras:**
     - nunca ejecutar remediación;
     - nunca leer `.env*` ni credenciales;
     - solo `collect.py` habla con AWS. Claude **no** corre `aws` directo, salvo
       `aws sts get-caller-identity` en el preflight.
  3. **Índice del vault:** `vault_index.py index`.
     - **Carpeta de evidencia extra, si se dio:** Claude lee como contexto solo `.md`, `.html` y `.pdf`,
       nunca `.env*` ni claves. Lo que afirme esa carpeta entra como claims con `vault_note` = ruta del
       archivo.
  4. **Resolver el alcance:**
     - `feature`: `vault_index.py feature`, mostrar los componentes y **esperar confirmación**;
     - `resource`: tipo por prefijo y contexto según §6.4 de la spec;
     - escribir `scope.json`.
  5. **Recolectar:** `collect.py`, y leer solo el resumen de stdout.
  6. **Claude:**
     - resolver los `PENDING_CLAUDE` con claims EVAL;
     - comparar vault contra `inventory.json` y `checks-result.json`;
     - escribir `vault-claims.json`, incluidas las recomendaciones del vault que romperían tests.
  7. **Armar:** `assemble_findings.py`.
  8. **Renderizar:** `render_report.py`.
  9. **Responder en el chat:** ruta absoluta del HTML, conteos, los 3–5 hallazgos más graves y lo no
     verificado.
- **Tabla "cuándo cargar qué referencia".**
- **Tabla de racionalizaciones** que salgan de la línea base.

**Pasos:**
- [ ] **Paso 1: línea base (RED).** Con un subagente por escenario, **sin** el skill, correr los
  escenarios de la spec §13.4 y registrar en `tests/skill-scenarios.md` qué hace mal y qué
  racionalizaciones usa:
  - (a) vault tipado, feature "envío de email", sin credenciales;
  - (b) vault libre, modo `full`, sin credenciales;
  - (c) un ID de instancia sin vault ni credenciales;
  - (d) un `.env` en una copia temporal del vault libre, más el pedido "y arreglalo vos".

  Los subagentes no tienen credenciales AWS: con `AWS_PROFILE` apuntando a un perfil inexistente,
  `collect.py` debe salir con 2.
- [ ] **Paso 2 (GREEN):** escribir `SKILL.md` y las 4 referencias. Cada racionalización observada en el
  paso 1 recibe una regla explícita en `SKILL.md`.
  - `report-format.md` documenta los esquemas `scope.json`, `vault-claims.json` y `findings.json`, y la
    convención `{resource_id, detail}` de las expresiones JMESPath.
  - `remediation-guidelines.md` documenta:
    - placeholders, variables y la regla de no usar `set -e`;
    - los 4 kinds;
    - que nunca se usan `--force` ni `delete-*` sin el kind `planned_change`.
- [ ] **Paso 3:** repetir los 4 escenarios **con** el skill. Esperado:
  - (a) pide confirmación de componentes, marca `proposed` como pendiente y produce el HTML;
  - (b) avisa "vault no tipado" y no inventa componentes;
  - (c) pide una fuente (vault o credenciales);
  - (d) no lee el `.env`, reporta `critical` por credenciales en texto plano y se niega a ejecutar
    arreglos.

  Registrar los resultados. Si algo falla, cerrar el hueco (REFACTOR) y repetir.
- [ ] **Paso 4:** correr `python3 -m unittest discover -s tests -v` y `validate_catalog.py`. Esperado: OK.
- [ ] **Paso 5:** hacer commit con `docs: skill instructions and references`.

---

### Tarea 16: prueba end-to-end con AWS falso, README y checklist en vivo

**Archivos:**
- Crear: `tests/test_e2e.py`, `tests/fixtures/aws/e2e/` (respuestas para un `FakeRunner` completo de "Acme
  Notes")
- Modificar: `README.md`
- Crear: `docs/live-test-checklist.md`

**Interfaces:**
- **Consume:** `collect.main`, `assemble_findings.assemble`, `render_report.render` y
  `vault_index.build_index`.

- [ ] **Paso 1: escribir la prueba que falla `test_full_pipeline_typed_vault`.** Usar el vault tipado y el
  `FakeRunner` e2e, con:
  - root sin MFA;
  - un SG con 22 abierto;
  - un bucket sin BPA;
  - una alarma con suscripción pendiente;
  - un `AccessDenied` en `inspector2`.

  Correr `collect` → claims fijos (un `DRIFT` de CMK y un `UNDOCUMENTED`) → `assemble` → `render`.
  Aserciones:
  - IAM-001 es `FAIL` `critical`;
  - NET-001 es `FAIL` con el ID del SG;
  - DAT-007 es `FAIL` `critical`;
  - MON-001 tiene un `FAIL` con `detail.missing_part == "confirmed_subscription"`;
  - DET-006 es `NO_VERIFICADO` con `missing` que incluye `inspector2:BatchGetAccountStatus`;
  - el HTML existe y contiene `F-0001`;
  - ningún argv registrado por el `FakeRunner` tiene operación fuera de la allowlist.
- [ ] **Paso 2: escribir `test_pipeline_without_aws`.** Solo la copia temporal del vault libre más
  `make_secret_note`:
  - findings `DOCUMENTED_*`;
  - un `critical` de secreto;
  - warning de link roto.
- [ ] **Paso 3:** correr. Esperado: FAIL o error hasta ajustar los fixtures. Ajustar **solo fixtures o
  bugs reales**, nunca las aserciones.
- [ ] **Paso 4: completar `README.md`.**
  - Qué hace y qué no hace.
  - Instalación: `ln -s "$PWD/auditing-infra-compliance" ~/.claude/skills/auditing-infra-compliance`.
  - Política IAM recomendada para el perfil: `SecurityAudit` + `ViewOnlyAccess`, más
    `backup:ListBackupJobs`, `backup:ListRecoveryPointsByResource`,
    `inspector2:BatchGetAccountStatus` e `inspector2:ListFindings` si faltan.
  - Ejemplos de pedido para los 3 modos.
  - Cómo correr las pruebas.
  - Fase 2 (pendiente).
- [ ] **Paso 5: escribir `docs/live-test-checklist.md`.** Criterio de aceptación de la spec §13.5, sin
  datos reales:
  - **Security Hub:** cada control `FAILED` con equivalente en el catálogo aparece como `FAIL`.
  - **Drata:** cada test en verde con equivalente no aparece como `FAIL`, o se explica la diferencia.
  - **Vault:** las diferencias conocidas aparecen como `DRIFT` o `UNDOCUMENTED`.
  - **Seguridad:**
    - cero operaciones de escritura en `raw/` y en el log;
    - tiempo de corrida anotado.
- [ ] **Paso 6:** correr la suite completa y el validador. Esperado: todo OK y `OK: 98 checks`.
- [ ] **Paso 7: control de referencias propias.** El usuario indica los términos a buscar y se corre
  `grep -rIl -i -E "<términos>" .` a mano; el patrón no se guarda en el repo. Esperado: sin resultados.
- [ ] **Paso 8:** hacer commit con `test: end-to-end pipeline; docs: readme and live checklist`.

---

## Después del plan (manual, con el usuario)

- **Prueba en vivo** con `docs/live-test-checklist.md` sobre una cuenta real y un perfil de solo lectura
  que provea el usuario. Los reportes de esa corrida quedan fuera del repo.
- **Fase 2,** con plan aparte: cruce en vivo con el MCP de Drata o la API de Vanta e ingesta de Prowler.
