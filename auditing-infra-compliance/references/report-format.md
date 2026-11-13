# Formatos de archivos y del reporte

Se carga antes de escribir `scope.json`, `vault-claims.json` o `verification-claims.json`, y al leer `findings.json` o `verification.json`. Claude **escribe solo tres archivos** (`scope.json`, `vault-claims.json`, `verification-claims.json`); todo lo demás lo generan los scripts y no se edita a mano.

## 1. Carpeta de corrida

`./compliance-reports/<plataforma>-<alcance>-<YYYY-MM-DD-HHMM>/` en el directorio de trabajo, nunca dentro del vault. Ejemplo: `compliance-reports/acme-notes-feature-email-2026-11-12-1030/`.

| Archivo | Quién lo escribe |
|---|---|
| `scope.json`, `vault-claims.json`, `verification-claims.json` | Claude |
| `vault-index.json` (incluye `sensitive_files`) | `vault_index.py index` |
| `checks-result.json`, `inventory.json`, `raw/<CHECK_ID>/…` | `collect.py` |
| `findings.json` | `assemble_findings.py` |
| `verification.json` | `verify_remediation.py` |
| `report.html` | `render_report.py` |

Todo lo que se escribe está enmascarado: `AKIA…WXYZ` (4 últimos caracteres), emails `u***@dominio` (salvo los del tag `VantaOwner`), secretos `[REDACTED]`.

## 2. `scope.json`

```json
{"platform": "Acme Notes", "mode": "feature", "target": "envío de email",
 "regions": "auto", "profile": null,
 "resources": [
   {"type": "ses_identity", "id": "acme-notes.example", "region": "us-east-1"},
   {"type": "lambda_function", "id": "acme-notes-mailer", "region": "us-east-1"}
 ],
 "domains": null}
```

| Campo | Valor |
|---|---|
| `platform` | Nombre legible. |
| `mode` | `full` \| `feature` \| `resource`. |
| `target` | `null` en `full`; el texto de la feature o el id/ARN del recurso. |
| `regions` | `"auto"` (habilitadas con recursos + `us-east-1`) o lista, p. ej. `["us-east-1", "eu-west-1"]`. Una región no habilitada se omite con advertencia. |
| `profile` | Perfil AWS (`AWS_PROFILE`) o `null` para el entorno ya configurado. Es un nombre de perfil, nunca una clave. |
| `resources` | `[]` en `full`. En `feature` y `resource`: objetos `{type, id, region}`; `type` es una clave de `references/inventory.json` y `id` el id, nombre o ARN (tabla de mapeo en `references/vault-reading.md`). |
| `domains` | `null` (todos) o lista para acotar: `compute`, `data`, `detection`, `email`, `encryption`, `iam`, `integration`, `inventory`, `logging`, `monitoring`, `network`. |

En `feature` y `resource`, collect elige los chequeos de recurso cuyo tipo está en `resources` y los de cuenta que declaran ese contexto, y filtra los ofensores a esos recursos.

## 3. `vault-claims.json`

Lista de objetos. Todos los campos salvo `kind` pueden ser `null` u omitirse.

```json
[
  {"kind": "DRIFT", "check_id": "DAT-007",
   "resource": {"type": "s3_bucket", "id": "acme-notes-uploads", "region": "us-east-1"},
   "vault_note": "systems/Uploads Bucket.md",
   "vault_claim": "El bucket de uploads bloquea todo acceso público",
   "actual": "Block Public Access desactivado",
   "severity": null, "breaks_tests": []},
  {"kind": "EVAL", "check_id": "IAM-013", "resource": null,
   "status": "PASS", "detail": {"reason": "Las políticas administrativas están acotadas a un rol de emergencia"}}
]
```

| Campo | Significado |
|---|---|
| `kind` | `DRIFT` \| `UNDOCUMENTED` \| `DOCUMENTED_ONLY` \| `DOCUMENTED_GAP` \| `EVAL`. Otro valor se ignora con advertencia. |
| `check_id` | Id del catálogo (`DAT-007`) o `null` para una observación fuera del catálogo. Un id inexistente genera advertencia. |
| `resource` | `{type, id, region}` o `null`. Una región ausente en un recurso regional queda `__COMPLETAR_REGION__`; en cuenta/global es `us-east-1`. |
| `vault_note` | Ruta de la nota (o del archivo de evidencia) de donde sale la afirmación. |
| `vault_claim` | Lo que dice el vault, textual o parafraseado corto. |
| `actual` | Lo observado en la cuenta (o "no verificado: sin credenciales"). |
| `severity` | `critical` \| `high` \| `medium` \| `low` o `null`. Prioridad: `detail.severity_override` > `severity` del claim > severidad del catálogo (`low` para `UNDOCUMENTED` y claims sin chequeo). |
| `breaks_tests` | `[{"tool": "drata", "test": 30}]` o `[{"tool": "vanta", "test": "<nombre>"}]` si una recomendación del vault rompería esos tests. Convierte el claim en `DRIFT` de severidad al menos `high`. |
| `status`, `detail` | Solo en `EVAL`: `status` es un estado válido (`PASS`, `FAIL`, `N/A`, `NO_VERIFICADO`), `detail.reason` la justificación. |

**EVAL:** resuelve la fila `PENDING_CLAUDE` con el mismo `check_id` (el `resource` debe coincidir, salvo que la fila sea la de cuenta). Se puede escribir un `EVAL` `FAIL` por cada recurso ofensor. Sin claim, la fila queda `NO_VERIFICADO` con una advertencia. Los hallazgos de un `EVAL` salen marcados "evaluado por Claude".

**Observación fuera del catálogo:** `check_id: null`, `kind` `UNDOCUMENTED` o `DOCUMENTED_GAP`, y en `actual` o `vault_claim` la frase "observación de Claude, fuera del catálogo". Nunca lleva comandos de remediación ni mapeos propios.

## 4. `findings.json` (salida del ensamblador)

Claves de primer nivel: `meta`, `summary`, `findings`, `dependencies`, `coverage`, `warnings`, `notes`.

- Hallazgos que salen solos del índice del vault: cada `secrets_detected` y cada `sensitive_files` (`.env*`, `*.pem`, `*.key`, `*credentials*`, detectados solo por el nombre) generan un `FAIL` `critical` con `check_id: null` y remediación `console_only` (rotar y sacar el archivo).
- `meta`: plataforma, modo, target, fecha, `lang`, `catalog_checks`, `vault` (`path`, `kind`), `aws` (`account_id`, `identity_arn`, `regions`; `null` sin credenciales).
- `summary`: `by_status`, `by_severity_fail`, `drata_tests_failing`, `vanta_tests_failing`, `not_verified`. **Nunca hay porcentaje.**
- `findings[]`: `id` (`F-0001`…), `check_id`, `title`, `domain`, `status`, `severity`, `resource` (`type`, `id`, `region`, `name`), `evidence`, `vault_claim`, `vault_note`, `mappings`, `remediation`, `evaluated_by` (`script` \| `claude`), `vacuous`, `breaks_tests`, `missing` (permisos que faltan), `depends_on_me` (tests que dependen del recurso).
- `mappings`: `drata` (`test`, `name`, `source`), `vanta`, `tsc` y `iso27001_2022` (`id`, `sourced`), `security_hub`, `cis_aws`.
  - `sourced: "drata-dcf-2026-11-12"` = mapeo autoritativo tomado del catálogo DCF de Drata.
  - `sourced: false` = **inferido**; el HTML lo marca "inferido".
- `dependencies[]`: recursos de los que dependen tests que hoy pasan ("no tocar sin revisar").
- `coverage`: Anexo A y TSC con estado `FAIL` \| `NO_VERIFICADO` \| `PASS` \| `NOT_TOUCHED` y categoría (`organizational`, heredado de AWS…). Los organizacionales salen "fuera de alcance de este reporte".

### Estados

| Estado | Significado |
|---|---|
| `FAIL` | Verificado en vivo, no cumple |
| `PASS` | Verificado en vivo, cumple |
| `DRIFT` | El vault afirma algo distinto de la realidad |
| `DOCUMENTED_ONLY` | Solo vault: dice que cumple, no verificado |
| `DOCUMENTED_GAP` | Solo vault: dice que falta o está `proposed` |
| `UNDOCUMENTED` | Existe en la cuenta y el vault no lo menciona |
| `NO_VERIFICADO` | Sin credenciales o `AccessDenied` (con el permiso que falta) |
| `N/A` | No aplica; con `vacuous: true` = pase vacío (no hay recursos de ese tipo). **Nunca `PASS`.** |

### Severidades

| Severidad | Cuándo |
|---|---|
| `critical` | Exposición pública de datos o credenciales; root sin MFA o con access keys |
| `high` | Falla un test automático de Drata o Vanta |
| `medium` | Falla un control de Security Hub, CIS o FSBP sin test directo de Drata/Vanta |
| `low` | Higiene |

## 5. Convención `{resource_id, detail}` de los chequeos JMESPath

Para quien lee o extiende el catálogo: la expresión `verify.offenders` de un chequeo `jmespath` se pasa como `--query` y **proyecta una lista de objetos `{resource_id, detail}`**; cada uno es un ofensor y la lista vacía es `PASS`. `resource_id` puede omitirse cuando la llamada tiene `for_each` (se usa el valor iterado); un elemento que no es objeto se toma como `resource_id`. `detail` pasa a `evidence`. Un `detail.severity_override` cambia la severidad de ese ofensor. Claude no reevalúa PASS/FAIL de estos chequeos.

## 6. `verification.json` (salida de `verify_remediation.py`)

- `per_finding` (solo `FAIL` con remediación): `{"F-0005": {"status": "OK|REVISAR|CONFLICTO", "issues": [{"kind", "message", "source", "rule_id"}]}}`.
- `conflicts`: conflictos entre arreglos (reglas de `references/conflict-rules.json`).
- `gaps`: faltantes (`FAIL` sin comandos que no es `console_only`, `NO_VERIFICADO` con permiso faltante, recursos del inventario sin chequeo, arreglos sin `verify_after`).
- `apply_order`: ids de hallazgos en el orden sugerido de aplicación (identidad, logging y detección, claves KMS, cifrado, red, datos y backups, monitoreo, tags e integración; por severidad dentro de cada grupo y `planned_change` al final; una regla "A antes que B" gana).
- `completar_pendientes`, `cli_checked`, `summary` (`OK`, `REVISAR`, `CONFLICTO`), `warnings`.

Listar lo que Claude debe revisar (solo lectura):

```bash
python3 - "$RUN" <<'PY'
import json, sys
run = sys.argv[1]
f = json.load(open(f"{run}/findings.json"))["findings"]
v = json.load(open(f"{run}/verification.json"))["per_finding"]
for x in f:
    r = x.get("remediation") or {}
    s = v.get(x["id"], {}).get("status")
    if s in ("REVISAR", "CONFLICTO") or r.get("risk") in ("medium", "high"):
        print(x["id"], s, r.get("risk"), x["check_id"], x["resource"]["id"])
PY
```

## 7. `verification-claims.json`

```json
[
  {"finding_id": "F-0006", "status": "REVISAR",
   "message": "El bucket acme-notes-uploads lo usa el servicio de adjuntos según systems/Uploads Bucket.md.",
   "vault_note": "systems/Uploads Bucket.md"},
  {"finding_id": "F-0003", "status": "OK", "message": "Sin dependencias en el vault.", "vault_note": null}
]
```

`status`: `OK` \| `REVISAR` \| `CONFLICTO`. `message` y `vault_note` son texto o `null`. El script combina ambas fuentes y **gana el estado más severo**: un claim nunca baja un `CONFLICTO` del script. Un `OK` no cambia nada; un `status` fuera de `OK`\|`REVISAR`\|`CONFLICTO` se trata como `REVISAR`; un id desconocido se ignora; un claim con forma inválida se ignora con advertencia.

## 8. Qué ve el usuario en el HTML

Encabezado, resumen (conteos por estado y severidad, tests de Drata/Vanta afectados, lista de no verificado; sin porcentaje), filtros, tarjetas por severidad con chips de mapeo (marca "inferido" donde corresponde), evidencia, lo que afirma el vault, bloque de remediación con Copy, sello de verificación, "No tocar sin revisar", cobertura de normas, advertencias de la corrida y el pie "Pre-auditoría técnica automatizada. No es una opinión de auditoría ni cubre controles organizacionales.". Idioma por defecto: castellano; IDs, comandos y nombres de tests quedan en su idioma original.
