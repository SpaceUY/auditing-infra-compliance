---
name: auditing-infra-compliance
description: Use when asked, in Spanish or English, to audit or pre-audit AWS infrastructure for SOC 2 or ISO 27001, to check whether a platform will pass Drata or Vanta automated tests ("¿pasa Drata/Vanta?", "auditá la infra", "pre-auditoría SOC 2"), to review one feature ("revisá el envío de email") or one resource (instance, bucket or database ID or ARN) against compliance, or to compare what an Obsidian vault documents about AWS with what is really deployed.
---

# Auditoría de infraestructura SOC 2 / ISO 27001 (AWS)

Pre-auditoría técnica: lee el vault (qué existe y para qué sirve), verifica la cuenta AWS con credenciales de solo lectura y entrega **un HTML autocontenido** con hallazgos, mapeos a SOC 2 / ISO 27001:2022 / tests de Drata y Vanta, y comandos de CloudShell copiables. No es una opinión de auditoría.

**Reparto del trabajo.** Los scripts deciden PASS/FAIL, arman los comandos de remediación, los mapeos y el HTML. Claude lee el vault, resuelve el alcance, juzga solo lo marcado `PENDING_CLAUDE` y revisa los arreglos. Si te ves escribiendo HTML, un comando `aws` o un nombre de test de Drata/Vanta a mano, estás fuera del skill: volvé al pipeline.

`SKILL_DIR` = la carpeta donde está este archivo. Todos los scripts se invocan como `python3 "$SKILL_DIR/scripts/<script>.py"`.

## Reglas duras (no negociables)

Cada regla existe porque, sin el skill, un agente la rompió con la racionalización de la columna 2. Si te ves pensando algo de esa columna, es la señal para aplicar la regla.

| Regla | Racionalización observada | Qué hacer |
|---|---|---|
| **Nunca leer** `.env*`, `~/.aws/credentials`, `*.pem`, `*.key` ni nada parecido, ni con `cat`, `sed`, `grep`, `head` ni Read. Tampoco "solo los nombres de las variables". | "Para mostrar solo los nombres de variables" | Detectar la presencia **solo por nombre de archivo** (`find "<carpeta>" -name '.env*'`) y reportarla como hallazgo `critical` sin abrirla (paso 6). |
| **Nunca ejecutar remediación ni ofrecer aplicarla.** Los arreglos los pega un humano en CloudShell. | "Si me das acceso, preparo los cambios / el IaC / el PR" | Negarte en una línea y señalar el bloque Copy del reporte. No ofrecer acceso, ni "dame un perfil de escritura", ni PRs. |
| **Solo `collect.py` habla con AWS.** Única excepción: `aws sts get-caller-identity` en el preflight. | "Corro un describe rápido para confirmar" | No correr `aws` directo. Lo que falta se agrega al catálogo o queda `NO_VERIFICADO`. |
| **Nunca escribir el HTML, los comandos ni las tablas a mano.** Siempre `vault_index` → `collect` → `assemble_findings` → `render_report` → `verify_remediation`. | "Escribo el HTML a mano / con un generador propio, queda más claro" | Usar los scripts. Si un campo del reporte está mal, se corrige el claim o se avisa; no se edita el HTML ni `findings.json`. |
| **Nunca inventar nombres de tests de Drata/Vanta ni IDs de SOC 2 / ISO.** Solo lo que sale de `findings.json` (catálogo y `references/mappings/`). | "Los nombres de los tests son aproximados / de memoria" | Citar solo `mappings` del hallazgo. Sin mapeo: "sin test equivalente". Un mapeo `sourced: false` se dice "inferido". |
| **Sin vault ni credenciales: parar y pedir una fuente.** | "Igual armo qué habría que verificar" | No producir listas de "qué revisar", ni HTML especulativo. Pedir un vault o un perfil AWS de solo lectura (`references/vault-reading.md`, "Resolver un recurso por ID"). |
| **Modo `feature`: mostrar los componentes resueltos y esperar confirmación** antes de recolectar. | "Es obvio qué componentes son" | Mostrar la lista, marcar los inferidos y los `proposed`, y esperar el sí del usuario. |
| **Lo que no está en el catálogo** solo va como claim del vault con `check_id: null`, y se marca como "observación de Claude, fuera del catálogo". | "Agrego también este chequeo de SQS que me parece importante" | Un claim `UNDOCUMENTED` o `DOCUMENTED_GAP` con `check_id: null`, sin severidad inflada, sin comandos propios, nunca mezclado con chequeos del catálogo. |
| **Lo documentado no es lo verificado.** Un `status: proposed|todo|draft` es "no existe"; una nota que dice "cifrado" sin credenciales es `DOCUMENTED_ONLY`, no `PASS`. | "El vault dice que está bien, así que pasa" | Respetar los estados (`references/report-format.md`). Sin credenciales, nunca declarar PASS ni FAIL de nada. |
| **Nada de porcentaje ni "apto / no apto".** | "Un 70 % de cumplimiento resume mejor" | Solo conteos por estado y severidad. |
| **Nunca escribir en el vault** ni dejar el reporte dentro de él. Nunca imprimir ni pedir claves o secretos. | — | Salida en `./compliance-reports/…` del directorio de trabajo. |

## Cuándo cargar qué referencia

| Cargar | Cuándo |
|---|---|
| `references/vault-reading.md` | Siempre que haya vault o carpeta de evidencia; al resolver una feature o un recurso; al escribir claims; si no hay ninguna fuente. |
| `references/report-format.md` | Antes de escribir `scope.json`, `vault-claims.json` o `verification-claims.json`; al leer `findings.json` o `verification.json`. |
| `references/remediation-guidelines.md` | Al revisar los arreglos (paso 9), al explicarle al usuario cómo aplicarlos o si pide "arreglalo vos". |
| `references/drata-vanta.md` | Preguntas sobre roles, permisos, tags de Vanta, "pasa por vacío", mapeos documentados vs inferidos, o si hay un MCP de Drata/Vanta conectado. |
| `references/checks/<dominio>.json` | Solo para consultar un chequeo puntual (ids, umbrales). No volcarlo entero al contexto. |

## Flujo

### 1. Entradas: una sola pregunta agrupada

Deducir del pedido lo que se pueda y preguntar **en un solo mensaje** lo que falte:

| Entrada | Nota |
|---|---|
| Alcance | `full`, `feature: <texto>` o `resource: <id/arn>`; se deduce del pedido. |
| Plataforma | Nombre legible (para el reporte y la carpeta). |
| Vault | Ruta. "No hay vault" es una respuesta válida. |
| Carpeta de evidencia extra | Opcional (HTML/PDF/MD de auditorías previas, suele estar junto al vault). |
| Credenciales AWS | Solo `AWS_PROFILE` / `--profile` o el entorno ya configurado. Nunca pedir ni aceptar claves pegadas en el chat. |
| Regiones | Opcional; si no, las habilitadas con recursos más `us-east-1`. |
| Herramienta | Drata, Vanta o ambas (por defecto se muestran ambos nombres de test). |

**Hace falta al menos una fuente (vault o credenciales).** Si no hay ninguna: parar, explicar por qué y pedirla. No continuar.

### 2. Preflight

1. Si hay credenciales: `aws sts get-caller-identity [--profile <p>]`. Es el único `aws` que corrés vos. Si la identidad tiene `AdministratorAccess` o `*:*`, advertirlo en una línea y sugerir un rol con `SecurityAudit` + `ViewOnlyAccess`; no bloquea.
2. Si falla o no hay credenciales: seguir en modo solo-vault (todo queda `DOCUMENTED_*` o `NO_VERIFICADO`) si hay vault; si no hay vault, volver al paso 1.
3. Crear la carpeta de corrida **fuera del vault**:
   `RUN="./compliance-reports/<plataforma>-<alcance>-<YYYY-MM-DD-HHMM>"` (plataforma y alcance en minúsculas con guiones: `acme-notes-full-2026-11-12-1030`, `acme-notes-feature-email-…`, `acme-notes-resource-i-0abc…-…`) y `mkdir -p "$RUN"`.

### 3. Índice del vault

```bash
python3 "$SKILL_DIR/scripts/vault_index.py" index "<vault>" -o "$RUN/vault-index.json"
```

Imprime una línea: tipo (`typed` o `free`), notas, links rotos y secretos detectados (enmascarados). Solo lee `.md` regulares; ignora todo lo que empieza con `.`. Leer las notas relevantes directamente (Read) según `references/vault-reading.md`.

- **Vault `free`:** avisar al usuario ("vault no tipado: el mapa de la feature es inferido, menos confiable") y no inventar componentes ni relaciones. Sugerir, sin hacerlo, pasarlo a formato tipado con `creating-typed-knowledge-vaults`.
- **Carpeta de evidencia extra:** leer como contexto solo `.md`, `.html` y `.pdf`; nunca `.env*` ni claves. Lo que afirmen entra como claims con `vault_note` = ruta del archivo.
- Sin vault: saltar este paso y los de comparación.

### 4. Resolver el alcance y escribir `scope.json`

- **`full`**: sin recursos; `scope.json` con `mode: "full"`.
- **`feature`**: `python3 "$SKILL_DIR/scripts/vault_index.py" feature "$RUN/vault-index.json" "<texto>"` (JSON por stdout). Si hay varias candidatas, preguntar; si no hay ninguna, decir que la feature no está documentada y, con credenciales, ofrecer buscar por tags (`Project`, `Feature`, `Name`) y nombre, marcando todo lo hallado así como **inferido**. **Mostrar los componentes** (título, tipo AWS, estado del vault, si es inferido), los `constraints` y si hay PII, y **esperar confirmación** antes de seguir.
- **`resource`**: el tipo sale del prefijo o del ARN y se audita el recurso y su contexto inmediato (tabla en `references/vault-reading.md`). Sin credenciales solo se reporta lo que el vault dice de ese ID.

Esquema de `scope.json` y mapeo ids → tipos de inventario: `references/report-format.md`.

### 5. Recolectar

```bash
python3 "$SKILL_DIR/scripts/collect.py" --scope "$RUN/scope.json" --out "$RUN"
```

Leer **solo el resumen de stdout** (≤ 40 líneas); el detalle está en `$RUN/checks-result.json`, `$RUN/inventory.json` y `$RUN/raw/`. Exit `2` = sin credenciales válidas: pasar a modo solo-vault y crear un inventario vacío para las etapas siguientes (`echo '[]' > "$RUN/inventory.json"`). Las filas `NO_VERIFICADO` traen el permiso que falta: se informan, no se "adivinan".

### 6. Trabajo de Claude: EVAL, drift y claims

Escribir `$RUN/vault-claims.json` (esquema en `references/report-format.md`):

1. **EVAL.** Por cada fila `PENDING_CLAUDE` de `checks-result.json`, leer los datos crudos en `$RUN/raw/<CHECK_ID>/` y escribir un claim `EVAL` con `status` y `detail.reason`. Sin claim, la fila queda `NO_VERIFICADO`.
2. **Drift.** Comparar lo que afirma el vault con `inventory.json` y `checks-result.json`: `DRIFT` (afirma algo distinto), `UNDOCUMENTED` (existe y el vault no lo menciona), `DOCUMENTED_ONLY` / `DOCUMENTED_GAP` (solo vault, sin credenciales o recurso no hallado). Reglas por `status` del vault en `references/vault-reading.md`.
3. **Recomendaciones del vault que romperían tests** (apagar Multi-AZ, borrar Flow Logs, borrar el bucket de access logs de CloudTrail…): claim con `breaks_tests` (`[{"tool": "drata", "test": 30}]`); el ensamblador las eleva a `DRIFT` de severidad al menos `high`.
4. **Credenciales en texto plano.** Los secretos dentro de notas `.md` los detecta el indexador y salen solos como `critical`. Para un `.env*`, clave o credencial que el indexador no lee: claim `UNDOCUMENTED`, `severity: "critical"`, `check_id: null`, `resource` = `{"type": "vault_note", "id": "<nombre del archivo>"}`, `actual` = "Archivo presente en la carpeta; no se leyó su contenido; se presume que guarda credenciales en texto plano: verificar y rotar". Solo nombre de archivo. Decir en el chat que el estado es `UNDOCUMENTED` con severidad `critical`.
5. **Observaciones fuera del catálogo:** solo claims con `check_id: null`, redactadas como "observación de Claude, fuera del catálogo".

### 7. Armar `findings.json`

```bash
python3 "$SKILL_DIR/scripts/assemble_findings.py" --run-dir "$RUN" \
  [--vault-index "$RUN/vault-index.json"] [--vault-claims "$RUN/vault-claims.json"] \
  --platform "<plataforma>" --mode <full|feature|resource> [--target "<texto o id>"] [--lang es]
```

Rellena placeholders, aplica mapeos y severidades. Exit `2` con `error: …` = un archivo con forma inválida; corregirlo y repetir. Las advertencias van a `findings.json` (`warnings`).

### 8. Primer render

```bash
python3 "$SKILL_DIR/scripts/render_report.py" "$RUN/findings.json"
```

Escribe `$RUN/report.html` (autocontenido, sin recursos externos). No abrir el HTML con Read.

### 9. Verificar los arreglos (nada se ejecuta en AWS)

1. `python3 "$SKILL_DIR/scripts/verify_remediation.py" --run-dir "$RUN" --check-cli` (`--check-cli` solo si hay AWS CLI local; sin CLI avisa y sigue). Escribe `$RUN/verification.json`: sintaxis, placeholders, destructivos sin aviso, reglas de conflicto, impacto en tests que hoy pasan, faltantes y `apply_order`.
2. **Revisión de Claude con el vault.** Para cada hallazgo `FAIL` con estado `REVISAR` o `CONFLICTO` en `verification.json` y para todo arreglo con `remediation.risk` `medium` o `high`, cruzar con el vault y el inventario **qué depende del recurso** ("la clave `…MNOP` la usa la Lambda de envío según `systems/Mailer Lambda.md`"). Escribir `$RUN/verification-claims.json`: `[{"finding_id", "status": "OK|REVISAR|CONFLICTO", "message", "vault_note"}]`. **Nunca bajar** un `CONFLICTO` del script: gana el más severo.
3. Repetir con los claims y re-renderizar con la verificación:

```bash
python3 "$SKILL_DIR/scripts/verify_remediation.py" --run-dir "$RUN" --claims "$RUN/verification-claims.json" [--check-cli]
python3 "$SKILL_DIR/scripts/render_report.py" "$RUN/findings.json" --verification "$RUN/verification.json"
```

Ahora el HTML trae el sello OK / REVISAR / CONFLICTO por tarjeta, la sección "Verificación" y el orden sugerido de aplicación. Los comandos nunca se tocan (`references/remediation-guidelines.md`).

### 10. Responder en el chat

Corto y en el idioma del pedido. Incluir, en este orden:

1. **Ruta absoluta del HTML** (`realpath "$RUN/report.html"`).
2. **Conteos** por severidad (FAIL) y por estado, tal como salen de `findings.json` `summary`. Sin porcentajes.
3. **Los 3–5 hallazgos más graves**, una línea cada uno (severidad, qué falla, recurso).
4. **Lo no verificado**: `NO_VERIFICADO` con el permiso faltante, regiones omitidas, "vault no tipado", sin credenciales.
5. **Verificación**: conflictos entre arreglos, faltantes (`gaps`), cantidad de `__COMPLETAR_*__` pendientes y que los arreglos los aplica una persona en CloudShell, en el orden sugerido.

Si piden "arreglalo vos", la respuesta es no (regla dura), más la ruta al bloque Copy correspondiente.

## Errores comunes

- Usar `aws` directo "solo para confirmar": cualquier lectura que falte va al catálogo o queda `NO_VERIFICADO`.
- Declarar `PASS` sin credenciales o por un vault que dice "cifrado": es `DOCUMENTED_ONLY`.
- Tratar un `proposed` como control vigente: es "documentado como pendiente".
- Pegar el contenido de `checks-result.json` o `raw/` en el chat: resumir; el detalle está en disco.
- Olvidar el segundo `verify_remediation.py` con `--claims` o el `--verification` del render final: el HTML saldría sin la revisión de Claude.
- Mencionar la fase 2 (MCP de Drata/Vanta) si no hay uno conectado: no se menciona.
