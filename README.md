# infra-compliance-audit

Skill de Claude Code `auditing-infra-compliance`: pre-audita infraestructura AWS contra SOC 2 (TSC 2017) e ISO/IEC
27001:2022 y entrega **un HTML autocontenido** que dice si la infraestructura es óptima, con hallazgos, mapeos a los
tests de Drata y Vanta y comandos de CloudShell que una persona copia y pega. Está pensado para equipos de
ingeniería, DevOps y seguridad que preparan una auditoría (o quieren saber si la plataforma va a pasar los tests
automáticos de Drata o Vanta) y para quien mantiene un vault de Obsidian con la documentación de la infraestructura.

**Regla absoluta: el skill solo informa.** Produce un reporte y comandos de remediación para un humano; **nunca
escribe en AWS ni aplica un arreglo** (ni Claude ni los scripts), aunque se lo pidan, "solo para probar", con otra
herramienta o con un perfil de escritura. No ofrece acceso, PRs ni IaC para aplicarlo. Una persona pega los comandos
en CloudShell, después de leerlos.

**Fuente flexible: verifica lo que le den.** Evalúa con credenciales AWS de solo lectura, con un vault de Obsidian
(tipado o libre) o con ambos. El veredicto (`OPTIMAL` / `NOT_OPTIMAL` / `NOT_VERIFIABLE`) **siempre dice en qué se
basa** (`summary.verdict_basis`: `aws`, `vault` o `aws+vault`). Un veredicto basado solo en el vault nunca dice que AWS
verificó algo.

## Contenido

1. [Qué hace y qué no hace](#qué-hace)
2. [Cómo funciona](#cómo-funciona)
3. [Fuentes y veredicto](#fuentes-y-veredicto)
4. [Modos de uso](#modos-de-uso)
5. [Requisitos](#requisitos)
6. [Instalación](#instalación)
7. [Permisos AWS recomendados](#permisos-aws-recomendados)
8. [Uso paso a paso y archivos que genera](#uso-paso-a-paso-y-archivos-que-genera)
9. [Cómo leer el informe](#cómo-leer-el-informe)
10. [Etapa de verificación de los arreglos](#etapa-de-verificación-de-los-arreglos)
11. [Cobertura](#cobertura)
12. [Seguridad y privacidad](#seguridad-y-privacidad)
13. [Drata y Vanta conectados por MCP (fase 2)](#drata-y-vanta-conectados-por-mcp-fase-2)
14. [Limitaciones conocidas](#limitaciones-conocidas)
15. [Estructura del repositorio](#estructura-del-repositorio)
16. [Desarrollo](#desarrollo)
17. [Documentación](#documentación)

## Qué hace

- Lee un vault de Obsidian (tipado o libre) para saber qué debería existir y para qué sirve.
- Verifica la cuenta AWS con credenciales de **solo lectura**: inventario (33 tipos de recurso) más un catálogo de 98
  chequeos en once dominios (IAM, logging, detección, cifrado, red, cómputo, datos, monitoreo, inventario,
  integración y email; el detalle está en [Cobertura](#cobertura) y en `validate_catalog.py --list`).
- Compara lo documentado con lo desplegado y lo informa como `DRIFT`, `UNDOCUMENTED`, `DOCUMENTED_ONLY` o
  `DOCUMENTED_GAP`.
- Calcula un **veredicto** con la fuente que le den y dice en qué se basa (ver [Fuentes y veredicto](#fuentes-y-veredicto)).
  No hay porcentaje ni nota.
- Mapea cada hallazgo a criterios SOC 2, controles ISO 27001:2022 Anexo A, tests de Drata y tests de Vanta, y marca como
  "inferred" todo mapeo que no tiene fuente.
- Arma los comandos de remediación para CloudShell y **los verifica sin ejecutarlos** (sintaxis, valores pendientes,
  conflictos entre arreglos, tests que dependen del recurso); sugiere un orden de aplicación.
- Produce `report.html`, `findings.json`, `checks-result.json`, `inventory.json` y `raw/` en
  `./compliance-reports/<plataforma>-<alcance>-<fecha>/`, siempre fuera del vault.
- Muestra el progreso de la recolección y deja un resultado parcial utilizable si la corrida se corta.
- Los scripts deciden PASS/FAIL, arman los comandos, los mapeos y el HTML; Claude lee el vault, resuelve el alcance y
  juzga solo lo que los scripts no pueden decidir.

## Qué no hace

- **No escribe en AWS, jamás.** `aws_runner.py` admite solo `describe-*`, `list-*` y `get-*` (más `lookup-events`,
  `generate-credential-report` y la excepción acotada `inspector2 batch-get-account-status`), rechaza una denylist de
  lecturas que exponen secretos y las operaciones de nombre sensible (credential, password, token, secret…) salvo
  excepciones revisadas, y rechaza todo argumento `https://` o `http://` (la CLI intentaría descargarlo). Además solo
  corre los pares (servicio, operación) de `catalog.REVIEWED_OPERATIONS`: agregar una llamada exige agregarla ahí y
  `validate_catalog.py` falla si falta.
- **No aplica arreglos, ni siquiera si se lo piden o "para probar":** los comandos los pega una persona en
  CloudShell. Tampoco ofrece acceso de escritura, PRs ni IaC. Los arreglos que reemplazan una política o configuración
  leen primero la actual y se detienen (`STOPPED`) si no pueden leerla; ninguno se ejecuta desde el skill.
- No es una opinión de auditoría ni un puntaje: no hay porcentaje ni nota de cumplimiento, solo conteos por estado y
  severidad, y el veredicto con su base.
- No evalúa controles organizacionales (políticas, análisis de riesgo, capacitación, RRHH, proveedores, gestión del
  ISMS): los lista como "fuera de alcance de este reporte" para que nadie lea "todo verde" como "apto para SOC 2".
- No lee archivos `.env*`, `~/.aws/credentials`, `*.pem` ni `*.key`; los detecta solo por nombre. La detección de
  secretos dentro de las notas tiene límites conocidos (ver [Limitaciones](#limitaciones-conocidas)).
- No escribe en el vault, ni deja el reporte dentro de él.
- No inventa nombres de tests de Drata o Vanta ni IDs de SOC 2 o ISO: usa solo lo que sale del catálogo y de
  `references/mappings/`.
- No cubre Windows (Linux y macOS), otras nubes, varias cuentas en una corrida ni repositorios de código o IaC, y no
  consulta a Drata o Vanta en vivo salvo que haya un MCP conectado (ver [Fase 2](#drata-y-vanta-conectados-por-mcp-fase-2)).

## Cómo funciona

El skill es un pipeline de cinco scripts de línea de comandos. Claude los orquesta y hace solo el trabajo que requiere
lectura y criterio; no escribe HTML, comandos `aws` ni nombres de tests a mano.

```mermaid
flowchart LR
    V[(Vault de Obsidian)] --> VI[vault_index.py]
    A[(Cuenta AWS<br/>solo lectura)] --> C[collect.py]
    VI -->|vault-index.json| CL{{Claude: alcance,<br/>EVAL, drift, claims}}
    CL -->|scope.json| C
    C -->|checks-result.json<br/>inventory.json, raw/| CL
    CL -->|vault-claims.json| AF[assemble_findings.py]
    VI --> AF
    C --> AF
    AF -->|findings.json| R1[render_report.py]
    R1 -->|report.html| VR[verify_remediation.py]
    VR -->|verification.json| CL2{{Claude: cruza con<br/>el vault}}
    CL2 -->|verification-claims.json| VR
    VR --> R2[render_report.py<br/>--verification]
    R2 -->|report.html con sellos| P([Una persona pega los arreglos<br/>en CloudShell])
```

| Etapa | Script | Qué hace | Quién decide |
|---|---|---|---|
| 1 | `vault_index.py index` / `feature` | Indexa el vault (solo `.md`, enmascarado) y resuelve los componentes de una feature | Script |
| 2 | (alcance) | Escribe `scope.json`: modo, regiones, recursos, dominios | Claude |
| 3 | `collect.py` | Inventario y chequeos de lectura contra AWS; PASS/FAIL, `NOT_VERIFIED` con el permiso que falta | Script |
| 4 | (claims) | Resuelve las filas `PENDING_CLAUDE`, compara el vault con la realidad (drift) y escribe `vault-claims.json` | Claude |
| 5 | `assemble_findings.py` | Une todo en `findings.json`: placeholders, mapeos, severidades, cobertura, veredicto | Script |
| 6 | `render_report.py` | Genera `report.html` (plantilla fija, sin recursos externos) | Script |
| 7 | `verify_remediation.py` | Verifica los comandos de remediación sin ejecutarlos y ordena la aplicación | Script |
| 8 | (revisión) | Cruza los arreglos riesgosos con el vault y escribe `verification-claims.json` | Claude |
| 9 | `verify_remediation.py --claims` + `render_report.py --verification` | Verificación final y HTML con sellos | Script |

De los 98 chequeos del catálogo, solo uno (IAM-013, "políticas propias con comodines amplios") lo juzga Claude
(`PENDING_CLAUDE`); el resto lo evalúan los scripts (expresión JMESPath que ejecuta la propia AWS CLI con `--query`,
evaluadores Python o consultas DNS). Claude no reevalúa un PASS o FAIL del script.

## Fuentes y veredicto

Hace falta **al menos una fuente**: un vault, credenciales AWS de solo lectura, o ambos.

| Fuentes | Qué se evalúa | `verdict_basis` |
|---|---|---|
| Solo credenciales AWS | Lo real: inventario descubierto y catálogo de chequeos | `aws` |
| Solo vault | Lo documentado: nada se marca `PASS` ni `FAIL`; los hallazgos son `DOCUMENTED_*` | `vault` |
| Credenciales y vault | Lo real, más las diferencias entre lo documentado y lo desplegado (drift) | `aws+vault` |
| Ninguna | No hay reporte: `assemble_findings.py` termina con exit `2` ("sin fuentes") | |

El veredicto está en `summary.verdict` (`OPTIMAL`, `NOT_OPTIMAL` o `NOT_VERIFIABLE`), con su frase en
`summary.verdict_text` y sus motivos en `summary.verdict_reasons`; es lo primero que muestra el HTML, junto a la base.
El orden de gravedad es `NOT_OPTIMAL` > `NOT_VERIFIABLE` > `OPTIMAL`.

**Con credenciales (base `aws` o `aws+vault`):**

| Veredicto | Cuándo |
|---|---|
| `NOT_OPTIMAL` | Algún `FAIL`; un `DRIFT` o `UNDOCUMENTED` con `actual_status: FAIL` (lo real incumple); o una `DOCUMENTED_GAP` crítica o alta |
| `NOT_VERIFIABLE` | Corrida parcial, regiones bloqueadas por SCP, incomplete inventory, algo `NOT_VERIFIED` o solo documentado, componentes del alcance sin verificar, o ningún `PASS` ni `FAIL` evaluado |
| `OPTIMAL` | Corrida completa, nada sin verificar y al menos un `PASS` o `FAIL` evaluado |

**Solo con el vault (base `vault`):**

| Veredicto | Cuándo |
|---|---|
| `NOT_OPTIMAL` | Una `DOCUMENTED_GAP` crítica o alta, un secreto o archivo sensible detectado, o un claim con `actual_status: FAIL` |
| `OPTIMAL` | Al menos un control documentado en el alcance, ninguna brecha documentada y nada del alcance sin documentar; sigue siendo "not verified against AWS" |
| `NOT_VERIFIABLE` | Todo lo demás; `verdict_reasons` dice qué componentes o controles el vault no documenta |

Ejemplos de `verdict_text`: "Optimal based on what the vault documents (not verified against AWS)", "Not optimal based on AWS:
…", "Optimal based on AWS and the vault".

**Drift (`DRIFT`).** Con ambas fuentes, la realidad manda: se compara lo que afirma el vault con `inventory.json` y
`checks-result.json`. Si el vault dice una cosa y la cuenta otra, el hallazgo es `DRIFT` y se muestran ambas versiones;
solo con `actual_status: FAIL` (lo real incumple el chequeo) conserva el arreglo completo. Un recurso vivo que el vault
no menciona es `UNDOCUMENTED` (severidad `low` por defecto; ISO 5.9 pide inventario de activos). Un `status` del vault
de `proposed`, `todo` o `draft` significa "no existe": se reporta como `DOCUMENTED_GAP` y nunca como control vigente.

**Sin credenciales:** el reporte avisa en el encabezado que nada se verificó contra AWS, muestra los conteos de lo
documentado y lo sin verificar en lugar de ceros que se lean como "limpio", y lista los componentes del alcance "sin
verificar".

Si el `scope.json` no selecciona nada (modo o dominio desconocido, recursos sin chequeos) o trae `scope.regions`
inválido, `collect.py` termina con exit `2` y un mensaje, sin escribir archivos. Si no se pueden listar las regiones
(`ec2:DescribeRegions`) en modo `auto`, los chequeos de cuenta con llamadas regionales quedan `NOT_VERIFIED`, nunca
`PASS` por mirar solo `us-east-1`.

## Modos de uso

El skill se activa solo cuando el pedido encaja (en español o inglés); el alcance se deduce de lo que se pide. Las
entradas que falten se preguntan en **un solo mensaje**: alcance, nombre de la plataforma, ruta del vault ("no hay
vault" es una respuesta válida), carpeta de evidencia extra (opcional), perfil AWS (opcional si hay vault), regiones
(opcional) y herramienta (`--tool drata|vanta|both`, opcional).

| Modo | Para qué | Ejemplo de pedido |
|---|---|---|
| `full` | Toda la cuenta | "Auditá la infraestructura de Acme Notes para SOC 2. El vault está en `~/vaults/acme-notes` y uso el perfil `acme-audit`." |
| `feature` | Un flujo o funcionalidad | "Revisá el envío de email de Acme Notes contra SOC 2." |
| `resource` | Un recurso por ID o ARN | "¿El bucket `acme-notes-uploads` pasa los tests de Drata?" o "Revisá `sg-0a1b2c3d4e5f60718` contra compliance." |

**Modo `feature`.** Con "revisá el envío de email", el skill busca la nota en el vault (`vault_index.py feature`),
resuelve sus componentes y **los muestra antes de recolectar**, marcando los inferidos y los pendientes (`proposed`), y
**espera tu confirmación**. Ejemplo de lo que muestra:

```
Feature "envío de email" → nota systems/Email delivery.md (vault tipado)
  1. SES Identity        ses_identity    shipped    example.com
  2. Mailer Lambda       lambda_function shipped    acme-notes-mailer
  3. Mail Queue          sqs_queue       shipped    acme-notes-mail-queue
  4. DMARC reject policy (sin recurso)   proposed   PENDING: no existe todavía
¿Confirmás esta lista, o agrego/quito algo?
```

Los componentes `proposed`, `todo` o `draft` no se auditan como recursos vivos: salen como `DOCUMENTED_GAP`. También
se listan aparte, como "contexto", los security groups, VPC, subnets y roles que rodean a la feature, para que
confirmes si entran al alcance. Si la feature no está documentada y hay credenciales, ofrece buscarla en el inventario
(por tags y nombre) y marca todo lo hallado como **inferido**. Con un vault libre avisa que el mapa de la feature es
inferido y menos confiable.

**Modo `resource`.** El tipo sale del prefijo (`i-…`, `sg-…`, `db-…`) o del ARN; se audita el recurso y su contexto
inmediato (para una instancia EC2: security groups, volúmenes, instance profile, subnet, Flow Logs de la VPC). Sin
credenciales solo se reporta lo que el vault dice de ese ID, y el skill lo avisa de entrada. Un pedido con un ID y sin
vault ni credenciales no avanza: pide una fuente.

## Requisitos

| Requisito | Detalle |
|---|---|
| Python 3.10 o superior | Solo biblioteca estándar, sin `pip install` |
| AWS CLI v2 | Con un perfil de solo lectura (o el entorno ya configurado) |
| bash | Para `verify_remediation.py` (`bash -n` sobre los comandos de remediación, sin ejecutarlos) |
| `dig` o `nslookup` | Opcional: chequeos de DNS (SPF y DMARC de SES). Sin ninguno, esos chequeos quedan `NOT_VERIFIED` |
| `node` y `jq` | Opcionales, solo para algunas pruebas (ver [Desarrollo](#desarrollo)); el skill no los necesita |
| AWS CloudShell | Donde una persona pega los arreglos, después de leerlos |
| Linux o macOS | Windows queda fuera |

## Instalación

Clonar el repo y enlazar la carpeta del skill en la carpeta de skills de Claude Code:

```bash
git clone <url-del-repo>
cd <carpeta-del-repo>
mkdir -p ~/.claude/skills
ln -s "$PWD/auditing-infra-compliance" ~/.claude/skills/auditing-infra-compliance
```

El skill queda disponible en la próxima sesión de Claude Code. Los scripts no requieren instalación.

## Permisos AWS recomendados

Usar un rol o usuario dedicado, de solo lectura, con las políticas administradas **`SecurityAudit`** y
**`ViewOnlyAccess`**. Si faltan, agregar además una política con estas acciones (que usan los chequeos de backups y de
Inspector):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "backup:ListBackupJobs",
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

- No usar una identidad con `AdministratorAccess`: el skill advierte con una línea `WARNING` (solo detecta la política
  administrada `AdministratorAccess` adjunta a la identidad) y sugiere un rol `SecurityAudit` + `ViewOnlyAccess`, pero no
  bloquea.
- Si alguien ofrece un perfil admin, Claude solo lo puede usar para la recolección de solo lectura que permiten los
  scripts, y nunca para aplicar un arreglo.
- Nunca pegar claves en el chat; indicar solo el nombre del perfil (`AWS_PROFILE` o el campo `profile` del
  `scope.json`).
- Si falta un permiso, el chequeo correspondiente queda `NOT_VERIFIED` e indica cuál es. Si una SCP niega la lectura,
  la fila dice "blocked by SCP" y no se pide ningún permiso (no es un permiso que falte en el perfil).
- Si el perfil ya venció (`ExpiredToken`, `InvalidClientTokenId`), renovarlo (por ejemplo `aws sso login --profile
  <perfil>`); el skill nunca pide claves pegadas.

## Uso paso a paso y archivos que genera

Lo normal es pedírselo a Claude (ver [Modos de uso](#modos-de-uso)); él corre el pipeline. Para repetirlo a mano, o
entender qué hace en cada paso:

```bash
SKILL_DIR="/ruta/absoluta/a/auditing-infra-compliance"
RUN="/ruta/absoluta/compliance-reports/acme-notes-full-2026-11-12-1030"
mkdir -p "$RUN"

# 1. Índice del vault (opcional; no se escribe dentro del vault)
python3 "$SKILL_DIR/scripts/vault_index.py" index "<vault>" -o "$RUN/vault-index.json"
# solo modo feature: resolver los componentes de una feature (JSON por stdout)
python3 "$SKILL_DIR/scripts/vault_index.py" feature "$RUN/vault-index.json" "envío de email"

# 2. Escribir $RUN/scope.json (ver el ejemplo de abajo)

# 3. Recolectar (solo lectura); --quiet apaga el progreso por stderr
python3 "$SKILL_DIR/scripts/collect.py" --scope "$RUN/scope.json" --out "$RUN" [--quiet]

# 4. (Claude) escribir $RUN/vault-claims.json

# 5. Armar findings.json
python3 "$SKILL_DIR/scripts/assemble_findings.py" --run-dir "$RUN" \
  [--vault-index "$RUN/vault-index.json"] [--vault-claims "$RUN/vault-claims.json"] \
  --platform "Acme Notes" --mode full [--target "<texto o id>"] [--tool drata|vanta|both]

# 6. Primer render
python3 "$SKILL_DIR/scripts/render_report.py" "$RUN/findings.json"

# 7. Verificar los arreglos (--check-cli solo si hay AWS CLI local)
python3 "$SKILL_DIR/scripts/verify_remediation.py" --run-dir "$RUN" [--check-cli]

# 8. (Claude) escribir $RUN/verification-claims.json solo si hay algo que revisar; después:
python3 "$SKILL_DIR/scripts/verify_remediation.py" --run-dir "$RUN" --claims "$RUN/verification-claims.json" [--check-cli]
python3 "$SKILL_DIR/scripts/render_report.py" "$RUN/findings.json" --verification "$RUN/verification.json"
```

Ejemplo de `scope.json` (modo `feature`):

```json
{"platform": "Acme Notes", "mode": "feature", "target": "envío de email",
 "regions": "auto", "profile": null,
 "resources": [
   {"type": "ses_identity", "id": "example.com", "region": "us-east-1"},
   {"type": "lambda_function", "id": "acme-notes-mailer", "region": "us-east-1"}
 ],
 "domains": null}
```

| Campo | Valor |
|---|---|
| `platform` | Nombre legible (para el reporte y la carpeta) |
| `mode` | `full`, `feature` o `resource` |
| `target` | `null` en `full`; el texto de la feature o el id/ARN del recurso |
| `regions` | `"auto"` (regiones habilitadas con recursos, más `us-east-1`) o una lista **no vacía** de regiones, p. ej. `["us-east-1", "eu-west-1"]`. Una región no habilitada se omite con una advertencia |
| `profile` | Nombre de perfil AWS o `null` para el entorno ya configurado. Nunca una clave |
| `resources` | `[]` en `full`; en `feature` y `resource`, objetos `{type, id, region}` con `type` de `references/inventory.json` |
| `domains` | `null` (todos) o una lista para acotar: `compute`, `data`, `detection`, `email`, `encryption`, `iam`, `integration`, `inventory`, `logging`, `monitoring`, `network` |

El `scope.json` se guarda en la carpeta de la corrida y no se mueve ni se borra antes de ensamblar:
`assemble_findings.py` lo lee de ahí para listar los componentes "sin verificar".

### Regiones

`scope.regions` decide dónde se recolecta. En modo `auto` se inventarían las regiones habilitadas con recursos más
`us-east-1`; los chequeos "en todas las regiones" (GuardDuty, Config, Access Analyzer, CloudTrail…) recorren las
regiones habilitadas. En cuentas con muchas regiones conviene acotar la lista para acortar la corrida. Las regiones
que una SCP bloquea se descartan con aviso, se informan como no verificadas (nunca como cumplidas) y quedan en
`aws.blocked_regions`.

### Carpeta de la corrida

`./compliance-reports/<plataforma>-<alcance>-<YYYY-MM-DD-HHMM>/` en el directorio de trabajo, nunca dentro del vault
(el repo ignora `compliance-reports/`). Ejemplos: `acme-notes-full-2026-11-12-1030`,
`acme-notes-feature-email-2026-11-12-1030`.

| Archivo | Quién lo escribe | Contenido |
|---|---|---|
| `scope.json` | Claude | Alcance resuelto (modo, regiones, recursos, dominios) |
| `vault-index.json` | `vault_index.py index` | Notas, aristas, IDs de AWS, links rotos, `secrets_detected` (patrón, nunca el valor) y `sensitive_files` (solo nombre) |
| `inventory.json` | `collect.py` | Inventario normalizado de la cuenta (vacío sin credenciales) |
| `raw/<CHECK_ID>/` | `collect.py` | Salida cruda de cada llamada (enmascarada), con el `argv` ejecutado |
| `checks-result.json` | `collect.py` | Una fila por chequeo y recurso (`PASS`, `FAIL`, `N/A`, `NOT_VERIFIED`, `PENDING_CLAUDE`), advertencias y, si la corrida se cortó, `partial` y `pending_checks` |
| `vault-claims.json` | Claude | Claims `EVAL`, `DRIFT`, `UNDOCUMENTED`, `DOCUMENTED_ONLY` y `DOCUMENTED_GAP` |
| `findings.json` | `assemble_findings.py` | `meta`, `summary` (veredicto), `findings`, `dependencies`, `coverage`, `warnings`, `notes` |
| `verification-claims.json` | Claude | Revisión de arreglos contra el vault (solo si hay algo que revisar) |
| `verification.json` | `verify_remediation.py` | Sello por arreglo, conflictos, faltantes, `apply_order` |
| `report.html` | `render_report.py` | El informe: un solo archivo, CSS y JS inline, sin recursos externos |

Claude escribe solo tres archivos (`scope.json`, `vault-claims.json`, `verification-claims.json`). Todo lo demás lo
generan los scripts y no se edita a mano: si un campo del reporte está mal, se corrige el claim y se vuelve a
ensamblar. Todo lo que se escribe está enmascarado (ver [Seguridad y privacidad](#seguridad-y-privacidad)).

### Códigos de salida

| Script | `0` | `2` | Otros |
|---|---|---|---|
| `vault_index.py` | Índice o feature resuelta | Vault inválido, o `-o` dentro del vault | |
| `collect.py` | Corrida completa (también un alcance bien formado que ningún chequeo cubre: sin resultados y con advertencia) | Sin credenciales válidas (deja `checks-result.json` con `aws: null` y un `inventory.json` vacío) o `scope.json` mal formado (mensaje, sin archivos) | `130`: interrumpida (Ctrl-C, SIGTERM, timeout); deja el resultado parcial |
| `assemble_findings.py` | `findings.json` escrito | Archivo de entrada con forma inválida, o "no sources: a vault or read-only AWS credentials are required" (no escribe `findings.json`) | |
| `render_report.py` | `report.html` escrito | Falta `findings.json` o un JSON inválido | |
| `verify_remediation.py` | `verification.json` escrito (aunque haya `CONFLICT`: es un resultado, no un error) | Falta la carpeta o `findings.json`, o un JSON inválido | |
| `validate_catalog.py` | Catálogo válido | | `1`: problemas en el catálogo |

### Corridas largas

En modo `full` o en una cuenta grande la recolección tarda minutos:

- **Progreso:** `collect.py` imprime por stderr una línea por chequeo terminado (`[n/total] CHECK-ID`) y una por el
  inventario; `--quiet` las apaga. El resumen final (máximo unas 40 líneas, con los primeros cinco `WARNING`) sale por
  stdout; el detalle está en `checks-result.json`, `inventory.json` y `raw/`, y las advertencias completas en
  `warnings` de `checks-result.json`.
- **Resultado parcial:** `inventory.json` se escribe apenas termina el inventario y `checks-result.json` se
  actualiza cada unos 15 segundos con `"partial": true` y `pending_checks`. Una corrida cortada (exit `130`) deja el
  archivo parcial; `assemble_findings.py` lo declara en una advertencia ("PARTIAL result…") y el veredicto nunca es
  `OPTIMAL`. No hay una opción para correr solo los pendientes: se vuelve a ejecutar, acotando `domains` o `regions` en una
  carpeta nueva si hace falta.
- **Segundo plano:** conviene correrlo en segundo plano (o con un timeout generoso) y leer solo el resumen cuando termina.
- Las llamadas idénticas se reusan y la falla de una región o de un ítem no tira todo el chequeo: esa región queda
  `NOT_VERIFIED` y las sanas conservan su resultado.

## Cómo leer el informe

Abrir `report.html` en el navegador (funciona sin conexión y se puede adjuntar como evidencia). De arriba abajo:

1. **Veredicto y base.** `Optimal`, `Not optimal` or `Not verifiable`, con la fuente en la que se apoya. Sin credenciales
   hay un aviso explícito de que nada se verificó contra AWS.
2. **Resumen.** Conteos por estado y por severidad (de las fallas), tests de Drata y Vanta que fallan, lista de lo no
   verificado y permisos que faltan. Tocar un conteo filtra los hallazgos. Sin porcentajes.
3. **Verificación de los arreglos** (si se corrió `verify_remediation.py`): conflictos, faltantes, orden de aplicación y
   cantidad de valores por completar.
4. **Filtros.** Severidad, estado, dominio, herramienta (Drata o Vanta), norma (SOC 2 o ISO 27001) y un buscador de
   texto; "Expandir todo" y "Contraer todo". Si se pasó `--tool`, el filtro de herramienta viene preseleccionado (ambas
   siguen disponibles). Los filtros se recuerdan en el navegador.
5. **Copy low-risk fixes** (ver más abajo).
6. **Tarjetas de hallazgo**, ordenadas por severidad: recurso y región, estado, severidad, chips de mapeo, evidencia, lo
   que afirma el vault, remediación y sello de verificación.
7. **No tocar sin revisar.** Recursos de los que dependen tests que hoy pasan (apagar Multi-AZ, borrar Flow Logs o el
   bucket de access logs de CloudTrail los pondría en rojo). Una recomendación del vault así se reporta como `DRIFT`
   `high` con "esta recomendación del vault rompería <test>".
8. **Cobertura de normas, advertencias de la corrida** (links rotos del vault, permisos faltantes, regiones omitidas,
   vault libre, resultado parcial) y el pie: "Pre-auditoría técnica automatizada. No es una opinión de auditoría ni
   cubre controles organizacionales."

Tiene modo claro y oscuro e impresión limpia.

### Estados

| Estado | Significado | ¿Lleva comandos de arreglo? |
|---|---|---|
| `FAIL` | Verificado en AWS: no cumple | Sí, completos |
| `PASS` | Verificado en AWS: cumple | No: solo "Verify with" |
| `DRIFT` | El vault afirma algo distinto de la realidad (se muestran ambas versiones) | Solo si lo real incumple (`actual_status: FAIL`) |
| `DOCUMENTED_ONLY` | Solo vault: dice que cumple, no verificado (severidad `low`; la del chequeo queda en la evidencia como "not verified") | No |
| `DOCUMENTED_GAP` | Solo vault: dice que falta o está `proposed` ("documentado como pendiente") | Sí, completos |
| `UNDOCUMENTED` | Existe en la cuenta y el vault no lo menciona (severidad `low` por defecto) | Solo si lo real incumple (`actual_status: FAIL`) |
| `NOT_VERIFIED` | No se pudo comprobar: falta un permiso (se indica cuál), "could not list the regions", "incomplete inventory", "blocked by SCP", sin credenciales | No |
| `N/A` | No aplica; con `vacuous` es un "pase por vacío" (no hay recursos de ese tipo). **Nunca `PASS`** | No |

Sin arreglo, la tarjeta muestra "Verify with" (el comando de solo lectura para comprobarlo) y la nota "no verificado:
no aplicar sin confirmar". Un hallazgo evaluado por Claude se marca "evaluado por Claude"; uno transcrito del vault, "no
verificado".

### Severidades

| Severidad | Cuándo |
|---|---|
| `critical` | Exposición pública de datos o credenciales; root sin MFA o con access keys; secretos o archivos sensibles junto al vault |
| `high` | Falla un test automático de Drata o Vanta |
| `medium` | Falla un control de Security Hub, CIS o FSBP sin test directo de Drata o Vanta |
| `low` | Higiene |

### Tipos de remediación (`remediation.kind`)

| `kind` | Qué es |
|---|---|
| `cli` | Uno o pocos comandos que arreglan el problema sin decisiones del usuario |
| `cli_with_decision` | Hay un valor que decide una persona (días de retención, email del owner, CIDR, ARN de una clave) o el comando reemplaza una configuración o política existente: trae un bloque de solo lectura previo y/o `__FILL_IN_…__` |
| `planned_change` | Multi-paso, destructivo o con downtime (cifrar una RDS existente, migrar una clave): pasos numerados, advertencia, riesgo y downtime. Nunca es "un comando" |
| `console_only` | No se puede por CLI (MFA del root): pasos en lenguaje llano, sin comandos |

Cada arreglo declara además `risk` (`low`, `medium`, `high`), `downtime` y un comando "verificar después". Los
comandos empiezan con las variables del bloque (`REGION=…`, `ACCOUNT_ID=…`) y nunca usan `set -e`.

### Valores a completar (`__FILL_IN_…__`)

Un valor que el skill no puede conocer, o que no es seguro inyectar en un comando (trae comillas, espacios, `$`), queda
como `__FILL_IN_<NAME>__` (por ejemplo `__FILL_IN_OWNER_EMAIL__`, `__FILL_IN_KMS_KEY_ARN__`,
`__FILL_IN_REGION__`). El HTML los resalta y los cuenta. **Hay que completarlos antes de pegar**; el skill nunca los
reemplaza con un valor plausible. El formato no es `<<…>>` porque en bash `<<` abre un heredoc.

### Botones de copia

- **Copy** (por bloque): copia un comando de CloudShell o el comando "verificar después".
- **Copy all**: aparece solo en los arreglos `cli` con más de un bloque. Los `cli_with_decision` y los
  `planned_change` se copian y se aplican bloque por bloque, leyendo cada uno.
- **Copy low-risk fixes** (por severidad): junta solo los arreglos `cli` de riesgo bajo, sin valores
  pendientes, que la verificación selló `OK`. Excluye los `REVIEW`, los `CONFLICT` y los que no tienen sello. Sin
  verificación vigente (nunca corrida o desactualizada) el botón está desactivado y dice por qué. Igual hay que leer
  los comandos antes de pegarlos.

### Tablas de cobertura y controles organizacionales

La sección "Cobertura de normas" tiene una tabla para ISO 27001:2022 (Anexo A) y otra para SOC 2 (TSC 2017). Cada
control tocado por los chequeos figura como `FAIL`, `NOT_VERIFIED`, `PASS` o `NOT_TOUCHED` (no tocado). Un control que
solo tocan hallazgos `DOCUMENTED_ONLY` o `DOCUMENTED_GAP` figura `NOT_VERIFIED` (el vault lo dice, nadie lo comprobó). Los
controles se agrupan en técnicos, heredados de AWS y **organizacionales: "fuera de alcance de este reporte"**; los
organizacionales que algún hallazgo toca se listan aparte como "mencionados por hallazgos", con el estado que viene del
hallazgo (el reporte no los evalúa). No es un indicador global de cumplimiento.

## Etapa de verificación de los arreglos

Después del primer render, `verify_remediation.py` revisa los comandos de remediación **sin ejecutar nada en AWS**:
solo corre `bash -n` y, con `--check-cli`, `aws <servicio> <operación> help` (ayuda local, sin tráfico a AWS; cada
`--flag` del comando debe aparecer en la ayuda). Escribe `verification.json` y asigna a cada arreglo un sello:

| Sello | Significado |
|---|---|
| `OK` | Sin observaciones |
| `REVIEW` | Una persona debe revisar algo antes de aplicar (valores sin completar, riesgo, dependencias, downtime) |
| `CONFLICT` | No aplicar tal cual: error de sintaxis, placeholder sin resolver, hygiene o conflicto entre arreglos |

Qué revisa (tipo de observación en `issues[].kind` y resultado):

| Revisión | Resultado |
|---|---|
| Sintaxis bash (`bash -n`) y, con `--check-cli`, operaciones y flags de la AWS CLI (`syntax`, `invalid_cli`) | `CONFLICT` |
| Un `{placeholder}` sin resolver (`unresolved_placeholder`) | `CONFLICT` |
| Higiene: `<<` o `set -e` (`hygiene`) | `CONFLICT` |
| Valores `__FILL_IN_*__` pendientes (`requires_fill_in`) | `REVIEW` |
| Comando destructivo (`delete-*`, `revoke-*`, `put-*-policy`, `--force`…) en un arreglo que no es `planned_change` ni `cli_with_decision` con aviso real (`destructive_without_warning`) | `REVIEW` |
| Toca un recurso del que dependen tests que hoy pasan (`dependency_impact`) | `REVIEW`, nombrando los tests |
| Declara `downtime: true` o riesgo `high` (`downtime`, `high_risk`): nunca queda en `OK` | `REVIEW` |
| Falta la evidencia que una regla necesita (`missing_evidence`), por ejemplo una instancia que usa el security group sin resultado de CMP-006 | `REVIEW` |
| Reglas de conflicto entre arreglos (`rule_conflict`, `CR-001`…`CR-010`) | `CONFLICT` o `REVIEW`, según la regla |

Reglas de conflicto (`references/conflict-rules.json`):

| ID | Situación | Resultado |
|---|---|---|
| CR-001 | Cerrar el puerto 80 (o todo el tráfico) de un security group que usa un balanceador de carga rompe la redirección HTTP a HTTPS | `CONFLICT` |
| CR-002 | CloudTrail con CMK: la key policy debe permitir a `cloudtrail.amazonaws.com` antes de aplicar; orden: la clave antes que el trail | `REVIEW` |
| CR-003 | Revocar SSH o RDP en un security group con una instancia no accesible por Systems Manager (CMP-006): quedás sin acceso; orden: primero habilitar SSM | `CONFLICT` |
| CR-004 | IMDSv2 obligatorio: SDK o agentes viejos que solo usan IMDSv1 dejan de obtener credenciales | `REVIEW` |
| CR-005 | Rotar o desactivar access keys: la app o el pipeline que la usa se rompe; rotar primero, desactivar después | `REVIEW` |
| CR-006 | `Deny` sin TLS en S3: los clientes que acceden por HTTP plano fallan | `REVIEW` |
| CR-007 | Cifrar un recurso existente (EBS, RDS, EFS) requiere una migración con downtime | `REVIEW` |
| CR-008 | Quitar `VantaNonProd` de un recurso de producción lo mete en el alcance de Vanta y puede abrir tests nuevos | `REVIEW` |
| CR-009 | Reemplazar una key policy puede dejar la clave inaccesible: conservar el statement de la cuenta root | `REVIEW` |
| CR-010 | Multi-AZ tiene costo adicional y un failover breve durante el cambio | `REVIEW` |

**Orden de aplicación (`apply_order`).** Identidad; logging y detección (visibilidad antes de tocar nada); claves KMS;
cifrado; red; datos y backups; monitoreo; tags e integración. Dentro de cada grupo, por severidad, con los
`planned_change` al final; una regla "A antes que B" gana.

**Revisión de Claude con el vault.** Para cada arreglo con `REVIEW` o `CONFLICT`, y para todo arreglo de riesgo
`medium` o `high`, Claude cruza con el vault y el inventario qué depende del recurso (por ejemplo, "la clave `…MNOP` la
usa la Lambda de envío según `systems/Mailer Lambda.md`") y lo escribe en `verification-claims.json`. El script combina
ambas fuentes y **gana el estado más severo**: Claude nunca baja un `CONFLICT` del script.

**Verificación desactualizada.** `verification.json` lleva una huella (`findings_digest`) de los hallazgos y sus
arreglos. Si se vuelve a correr `assemble_findings.py` después de verificar, `render_report.py` ignora la verificación,
el HTML muestra "stale verification: re-run verify_remediation", el botón de bajo riesgo queda
desactivado y hay que repetir `verify_remediation.py`.

## Cobertura

### Catálogo: 98 chequeos en 11 dominios

| Dominio | Chequeos | Qué cubre |
|---|---|---|
| `iam` | 17 | Root (MFA, hardware, access keys, uso), MFA de usuarios, política de contraseñas, rotación y credenciales sin uso, permisos por grupos, políticas administrativas, Access Analyzer, contacto de seguridad, IAM Identity Center |
| `logging` | 13 | CloudTrail (multi-región, validación, CMK, data events, bucket), métricas CIS, Flow Logs, retención y lifecycle de logs, access logs de ALB, logging de WAF, audit logs de EKS |
| `encryption` | 13 | EBS, RDS, EFS, S3, rotación y borrado de claves KMS, rotación de secretos (ENC-001..008); TLS en S3, ALB, RDS y vigencia de certificados ACM (TLS-001..005) |
| `data` | 11 | Backups y Multi-AZ de RDS, auto minor upgrade, deletion protection, PITR de DynamoDB, versionado y Block Public Access de S3, AWS Backup, ElastiCache |
| `monitoring` | 9 | Alarmas de CloudWatch con suscripción SNS confirmada (RDS, EC2, ALB, SQS, Lambda, ElastiCache) |
| `network` | 8 | Security groups y NACL (SSH, RDP, HTTP, todo el tráfico), SG por defecto, RDS público, WAF asociado |
| `detection` | 7 | GuardDuty, Security Hub, AWS Config, Inspector |
| `compute` | 6 | IMDSv2, instance profiles, balanceadores en 2 o más zonas, Auto Scaling, Systems Manager |
| `email` | 6 | SES: identidades y DKIM, TLS, configuration set, SPF, DMARC, acceso a producción |
| `inventory` | 4 | Tags de Vanta (`VantaOwner`, `VantaContainsUserData`, `VantaNonProd`) y tags organizacionales |
| `integration` | 4 | Roles y permisos de Drata (`DrataAutopilotRole`) y Vanta (`vanta-auditor`), key policies de KMS |

Los chequeos de email son propios del skill (ni Drata ni Vanta tienen tests de SES). `validate_catalog.py --list` da la
lista completa (`id | título | tipos de recurso | severidad`).

### Normas y herramientas

| | Fuente | Contenido |
|---|---|---|
| SOC 2 | `references/frameworks/tsc-2017.json` | Criterios TSC 2017 (revisión 2022 de los puntos de enfoque): 61 |
| ISO/IEC 27001:2022 | `references/frameworks/iso27001-2022.json` | 93 controles del Anexo A y 30 cláusulas (4 a 10) |
| Drata | `references/mappings/drata-dcf.json` | Snapshot (2026-11-12) de 130 tests Drata, cada uno con su control DCF y los requisitos SOC 2 e ISO; el catálogo referencia 58 tests |
| Vanta | `references/checks/*.json` | El catálogo referencia 41 tests de Vanta (mayormente los de CIS AWS) |

Los mapeos a SOC 2 e ISO de los chequeos con test de Drata salen del catálogo DCF (`sourced: "drata-dcf-2026-11-12"`); el
resto es **inferido** y el HTML lo marca así. Cada chequeo lleva además, cuando existen, su control de Security Hub
y su numeración de CIS AWS. Ejemplos de tests: Drata 214 "MFA for AWS Root Account", Drata 224 "AWS VPC Flow Logging",
Drata 104 "Cloud Storage Public Access Disabled"; Vanta "MFA is enabled on the root account", "VPC flow logging is
enabled in all VPCs", "CloudTrail is enabled in all regions". La lista completa está en el catálogo y en
`references/mappings/`.

### Lo que no cubre

- Controles organizacionales (políticas, análisis de riesgo, SoA, capacitación, background checks, MDM, RRHH,
  proveedores, cláusulas 4 a 10 del ISMS).
- Otras nubes, varias cuentas o una AWS Organization en una misma corrida (una cuenta por corrida), código o IaC.
- DynamoDB: no hay chequeo de cifrado (DynamoDB cifra siempre las tablas); solo entra al inventario y a los chequeos de
  backups y tags.
- Contactos alternativos de la cuenta: solo se verifica el de seguridad (IAM-016); no los de operaciones y facturación.

## Seguridad y privacidad

**Lectura únicamente, en capas.** Nada de lo siguiente depende de la buena voluntad de Claude:

| Capa | Qué hace |
|---|---|
| Lista cerrada de operaciones | `catalog.REVIEWED_OPERATIONS`: solo corren los pares (servicio, operación) revisados; `validate_catalog.py` rechaza un chequeo con un par que no esté ahí y `collect.py` no ejecuta ninguno fuera de la lista, aunque alguien edite el catálogo |
| Regla de prefijos | `aws_runner.py` solo admite `describe-*`, `list-*` y `get-*`, más `lookup-events`, `generate-credential-report` y la excepción acotada `inspector2 batch-get-account-status` |
| Regla de nombres | Rechaza operaciones de nombre sensible (credential, password, token, secret, private-key, embed-url, download-url, access-details, records, shard-iterator) salvo excepciones revisadas (el credential report, la política de contraseñas, `list-secrets`, `describe-secret`…) |
| Denylist | Rechaza lecturas que exponen secretos o datos aunque empiecen con `get-` o `list-` (`secretsmanager get-secret-value`, `ssm get-parameter*`, `lambda get-function`, `s3api get-object`, `kms decrypt`, `logs get-log-events`, `dynamodb get-item`/`scan`/`query`, `ec2 get-password-data`, `s3 *`, `rds-data *`, entre otras) |
| Chequeo de argumentos | Rechaza `--with-decryption`, `--include-value(s)`, `--endpoint-url`, `--profile`, `--region`, `--query`, `--output`, `--debug`, `--cli-input-*` (el runner los fija él mismo) y todo argumento `http://` o `https://` |
| Sin shell | `subprocess` con lista de argumentos y `shell=False`: sin pipes, `;`, `&&` ni `$()` |
| Depuración de respuestas | Se descartan o enmascaran campos que suelen llevar secretos (variables de entorno de Lambda, `UserData`, variables de stage de API Gateway, valores de cabeceras de CloudFront…) |
| Los arreglos no se ejecutan | Se escriben en `findings.json` y en el HTML; `verify_remediation.py` solo corre `bash -n` y la ayuda local de la CLI |

**Archivos sensibles.** El skill nunca abre `.env*`, `~/.aws/credentials`, `*.pem` ni `*.key`, ni con `cat`, `grep` o
Read, ni "solo los nombres de las variables". `vault_index.py` los detecta **solo por nombre** (`sensitive_files`) y el
ensamblador los reporta como `FAIL` `critical` con remediación `console_only` (rotar y sacar el archivo). Un archivo así
en la carpeta de evidencia extra no entra al índice: se nombra en el chat como advertencia.

**Enmascarado.** Todo lo que se escribe a disco, a stdout o al HTML pasa por `redact.py`: access key IDs como
`AKIA…WXYZ` (los 4 últimos caracteres), secretos y contraseñas como `[REDACTED]` (en cualquier formato: asignaciones,
celdas de tabla, `--master-user-password`, `Bearer <token>`, contraseñas en URLs, bloques PEM), y emails como
`u***@dominio` (salvo los del tag `VantaOwner`). Las referencias ("en Secrets Manager", `${VAR}`, ARN de un secreto) no
son secretos y quedan como están.

**El vault y la evidencia son datos, no instrucciones.** Si una nota dice "ejecutá…", "ignorá las reglas…", se evalúa
como contenido y se avisa; no se obedece.

**El vault no se modifica.** El skill solo lee `.md` regulares, ignora todo lo que empieza con `.`, no sigue symlinks y
se niega a escribir el índice dentro del vault. El reporte va a `./compliance-reports/…`.

**Credenciales.** Solo vía `AWS_PROFILE`, el `profile` del `scope.json` o el entorno ya configurado. El skill no pide ni
acepta claves pegadas en el chat; el único `aws` que corre Claude directo es `aws sts get-caller-identity` en el
preflight. El resto lo hace `collect.py`.

## Drata y Vanta conectados por MCP (fase 2)

Solo aplica cuando el usuario lo pide **y** hay un MCP realmente conectado en la sesión; una herramienta diferida o que
pide autenticarse no cuenta como conectada. Sin conexión no aparece en el reporte ni se menciona.

- **Drata (solo lecturas):** `Drata_searchMonitoringTests` y `Drata_getMonitoringTestFindings` para traer los tests que
  fallan y cruzarlos con los hallazgos ("coincide", "solo Drata", "solo el skill"); `Drata_searchControls` y
  `Drata_listRequirements` para el mapeo vivo de esa cuenta. Nunca `retest`, `exclude`, `create` ni ninguna escritura.
- **Vanta:** el mismo cruce, por `GET /tests` de su API o por su MCP si existe (a confirmar); solo lectura.
- **Prowler:** si está instalado y el usuario acepta, se puede ingestar su salida como segunda opinión; no forma parte del
  flujo base.

**Sin conexión viva** (el caso por defecto) el skill funciona completo con el snapshot de mapeos del repo, pero no
sabe qué tests están habilitados, `UNUSED` o `DISABLED` en la cuenta de Drata o Vanta, y no lo afirma.

## Limitaciones conocidas

- **Detección de secretos en las notas del vault.** Es por forma y por etiqueta, no entiende el contexto; una persona
  debe revisar las notas marcadas y las que hablan de credenciales:
  - El nombre de un secreto de Secrets Manager con forma de clave (20 o más caracteres mezclados) se marca como secreto:
    puede ser un falso positivo.
  - "password valor" sin separador (`:`, `=`, comillas o celda de tabla) no se detecta: se ve igual que la prosa.
  - En tablas por columnas, las columnas Clave, Secret, Token y API key son ambiguas: solo se enmascara un valor con forma
    de clave.
  - Un archivo sensible se detecta por su nombre y no se abre: nunca se sabe si contiene un secreto real.
  - Cada nota se lee hasta un tope de 2.000.000 de caracteres; una más larga queda en `truncated_notes` y el reporte lo
    avisa.
- **Numeración de CIS AWS.** Los números `cis_aws` del catálogo pueden venir de versiones distintas del benchmark (por
  ejemplo LOG-007 usa la numeración 1.4); la referencia verificable son los ids de Security Hub.
- **Retención de logs de 365 días.** Aplicarla a CloudWatch Logs es inferido para Drata (111) y Vanta.
- **Mapeos inferidos.** Los chequeos sin test de Drata (Config, Security Hub, Access Analyzer, política TLS del ALB, SES…)
  llevan mapeo a SOC 2 e ISO marcado "inferred".
- **ENC-001 (EBS por defecto)** evalúa las regiones con instancias EC2 (coincide con Drata 218), no todas las regiones.
- **IAM-004 (uso de root)** suma los logins de consola de root de todas las regiones habilitadas (hace falta
  `cloudtrail:LookupEvents` en cada una); el uso por API no se cuenta.
- **LOG-010 (lifecycle de logs):** las reglas seleccionadas por tag o por tamaño de objeto se ignoran.
- **Paginación.** La CLI pagina sola las operaciones que tienen paginador; las que no lo tienen (por ejemplo
  `wafv2 list-web-acls`) devuelven una sola página. Si la respuesta trae un token de siguiente página, `aws_runner.py` la
  trata como error ("respuesta truncada") y el chequeo queda `NOT_VERIFIED`: nunca un `PASS` sobre datos parciales, pero
  esa parte de la cuenta no se verifica.
- **Evidencia en `raw/`** escasa en los chequeos JMESPath, y el inventario no se copia ahí (el listado normalizado está
  en `inventory.json`).
- **Errores de red.** Un `Could not connect to the endpoint URL` queda `NOT_VERIFIED` (no se distingue de una falla de
  red) y nunca se toma por "sin recursos".
- **Un solo idioma.** El reporte sale solo en castellano (`--lang` está reservado y only accepts `en`); IDs, comandos y
  nombres de tests quedan en su idioma original.
- **Una cuenta por corrida.** No consolida AWS Organizations ni avisa del resto.
- Una cuenta de Drata o Vanta puede personalizar sus mapeos; sin conexión viva, el skill solo conoce los defaults.

## Estructura del repositorio

```
infra-compliance-audit/
├── README.md
├── auditing-infra-compliance/          el skill en sí (lo que se enlaza en ~/.claude/skills)
│   ├── SKILL.md                        flujo procedural, reglas duras y cuándo cargar cada referencia
│   ├── assets/report-template.html     plantilla del informe (CSS y JS inline, sin recursos externos)
│   ├── references/
│   │   ├── vault-reading.md            contrato del vault tipado, vault libre, features y recursos, secretos
│   │   ├── report-format.md            formatos de archivos, esquema de findings.json, estados, severidades
│   │   ├── remediation-guidelines.md   reglas de los comandos de CloudShell y la regla solo-informa
│   │   ├── drata-vanta.md              roles, permisos, tags y comportamiento de los tests; fase 2
│   │   ├── conflict-rules.json         reglas CR-001..CR-010 de la verificación
│   │   ├── inventory.json              33 tipos de recurso y cómo listarlos
│   │   ├── checks/<dominio>.json       catálogo de 98 chequeos en 11 dominios
│   │   ├── frameworks/                 catálogos embebidos: tsc-2017.json, iso27001-2022.json
│   │   └── mappings/drata-dcf.json     mapeo test de Drata, control DCF, SOC 2 e ISO (2026-11-12)
│   └── scripts/
│       ├── vault_index.py              índice del vault y resolución de features
│       ├── collect.py                  inventario y chequeos (paralelo por región, progreso, parcial)
│       ├── assemble_findings.py        findings.json, veredicto, cobertura
│       ├── render_report.py            findings.json a report.html
│       ├── verify_remediation.py       verificación de los arreglos
│       ├── validate_catalog.py         validador del catálogo; con --list lo lista
│       ├── aws_runner.py               único módulo que habla con AWS (solo lectura) y con dig/nslookup
│       ├── catalog.py                  carga y validación del catálogo; REVIEWED_OPERATIONS
│       ├── inventory.py                motor del inventario
│       ├── paths.py                    mini lenguaje de rutas del catálogo
│       ├── redact.py                   enmascarado de secretos, claves y emails
│       └── evaluators/                 evaluadores Python por dominio
├── docs/
│   ├── specs/2026-11-12-infra-compliance-audit-design.md    diseño (con los cambios posteriores a la aprobación)
│   ├── plans/2026-11-12-infra-compliance-audit.md           plan de implementación
│   ├── research/                       investigación: mapeos, tests de Drata y Vanta, referencias SOC 2
│   └── live-test-checklist.md          prueba en vivo, manual, con una cuenta real
└── tests/                              pruebas con un AWS falso (FakeRunner) y fixtures de la plataforma ficticia Acme Notes
    ├── skill-scenarios.md              escenarios de comportamiento del skill (con subagentes)
    ├── helpers.py, dom_smoke.js        utilidades de prueba
    └── fixtures/                       vaults tipado y libre, respuestas de AWS, alcances, claims
```

## Desarrollo

```bash
python3 -m unittest discover -s tests          # toda la suite
python3 -m unittest discover -s tests -v       # detalle
python3 auditing-infra-compliance/scripts/validate_catalog.py          # valida el catálogo
python3 auditing-infra-compliance/scripts/validate_catalog.py --list --type rds_instance --grep cifrado
```

- Las pruebas usan solo la biblioteca estándar y un AWS falso (`tests/helpers.py`, `FakeRunner`): no llaman a AWS ni a la
  red y escriben solo en directorios temporales. Algunas se omiten si falta una herramienta opcional: `node`
  (`tests/dom_smoke.js` ejecuta el script del HTML contra un DOM de mentira) y `jq`.
- `tests/test_e2e.py` recorre el pipeline completo con una cuenta ficticia de Acme Notes (cuenta `111122223333`, región
  `us-east-1`): recolección, `findings.json`, HTML, verificación y HTML con verificación; también el caso sin AWS.
- `tests/test_skill_docs.py` comprueba que `SKILL.md`, las referencias y este README no se desfasen del código (scripts,
  flags, mensajes y reglas citadas).
- **Validar el catálogo:** `validate_catalog.py` comprueba IDs únicos, campos obligatorios, que cada operación esté en
  `REVIEWED_OPERATIONS`, que cada arreglo que no es `console_only` tenga `verify_after`, que cada `planned_change` tenga
  pasos y advertencia, que los criterios TSC y los controles ISO existan en los catálogos embebidos y que las reglas de
  conflicto citen chequeos existentes. Imprime `OK: N checks, M reglas de conflicto` o termina con exit `1`.
- **Agregar un chequeo:**
  1. Elegir el dominio y agregar el objeto a `references/checks/<dominio>.json`: `id` único, `title`, `scope`,
     `resource_types`, `severity`, `not_enabled_means`, `verify` (llamadas, `evaluator` y `needs`), `vault_signals`,
     `mappings` y `remediation` (con `kind`, `risk`, `downtime`, comandos o pasos y `verify_after`). Puede usar como
     modelo cualquier chequeo existente del mismo dominio.
  2. Si usa una operación nueva, agregar el par (servicio, operación) a `catalog.REVIEWED_OPERATIONS` después de revisar
     qué devuelve (que no exponga secretos); sin eso `validate_catalog.py` lo rechaza.
  3. Si necesita lógica cruzada, escribir el evaluador `python:<nombre>` en `scripts/evaluators/<dominio>.py` y probarlo
     en `tests/test_eval_<dominio>.py`.
  4. Para los mapeos, usar solo tests y IDs que existan en `references/mappings/drata-dcf.json` y en
     `references/frameworks/`; un mapeo sin fuente va marcado como inferido.
  5. Correr `validate_catalog.py` y `validate_catalog.py --list --grep <id>` para ver la línea del chequeo, y después la
     suite completa. Si cambia el conteo, actualizar las cifras de este README y de la documentación.
- **Escenarios del skill:** `tests/skill-scenarios.md` describe los escenarios de comportamiento (vault tipado con una
  feature sin credenciales, vault libre en modo `full`, un ID sin fuente, tentaciones como un `.env` o "arreglalo vos").
  Se corren con subagentes, primero sin el skill (línea base) y después con el skill, y con `AWS_PROFILE` apuntando a un
  perfil inexistente.
- **Prueba en vivo:** `docs/live-test-checklist.md` es la lista de verificación manual contra una cuenta real con
  estado conocido en Drata (o Vanta) y Security Hub. No es un puntaje: son discrepancias explicadas. Ningún dato de esa
  cuenta se guarda en el repo.

## Documentación

- [Diseño](docs/specs/2026-11-12-infra-compliance-audit-design.md): objetivos, anti-objetivos, flujo, reglas de
  seguridad; la sección 16 ("Cambios posteriores a la aprobación") manda donde difiere del resto.
- [Plan de implementación](docs/plans/2026-11-12-infra-compliance-audit.md)
- [Investigación](docs/research/): mapeo de normas a AWS (`frameworks-aws-mapping.md`), tests de Drata y Vanta
  (`vanta-drata-tests.md`, `drata-dcf-mapping.json`), referencias de infraestructuras SOC 2 y revisión de otro skill.
- [Prueba en vivo](docs/live-test-checklist.md)
- [Escenarios del skill](tests/skill-scenarios.md)
- Dentro del skill: [`SKILL.md`](auditing-infra-compliance/SKILL.md) y `auditing-infra-compliance/references/`.
