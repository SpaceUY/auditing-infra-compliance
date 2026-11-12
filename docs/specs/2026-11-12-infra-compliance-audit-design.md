# Diseño: skill de auditoría de infraestructura SOC 2 / ISO 27001

Fecha: 2026-11-12 · Estado: borrador para aprobación · Carpeta: `trabajo/skills/infra-compliance-audit/`

Las decisiones marcadas **[decisión del diseñador]** no las tomó el usuario; están para que las revise.
Las fuentes de investigación están en la sección 15.

---

## 1. Intención

Una organización que opera varias plataformas en AWS que pasan, o van a pasar, auditorías SOC 2 e ISO 27001. Su
cumplimiento lo monitorean **Drata o Vanta**, según la plataforma. Hoy, descubrir qué va a hacer fallar un
test de Drata o Vanta exige revisar la consola a mano, o esperar a que la herramienta lo marque en rojo.

El skill hace una **pre-auditoría técnica de la infraestructura**:

1. Lee el vault de Obsidian de la plataforma para saber **qué existe y para qué sirve**.
2. Con credenciales AWS de **solo lectura**, verifica **cómo está configurado en realidad**.
3. Produce un **`.html` autocontenido**. Cada problema muestra:
   - qué falla y por qué importa (criterio SOC 2, control ISO 27001:2022 y test de Drata/Vanta equivalente);
   - la evidencia que lo prueba;
   - el comando o los comandos de **AWS CloudShell** que lo arreglan, con un botón **Copy**.

El objetivo práctico es que los tests automáticos de Drata y Vanta **no salten**. No se busca emitir una
opinión de auditoría.

## 2. Objetivos, no-objetivos y anti-objetivos

**Objetivos**
- **G1. Tres alcances:**
  - toda la infraestructura (`full`);
  - una feature de una plataforma, por ejemplo "revisá el envío de email" (`feature`);
  - un recurso puntual, por ID o ARN (`resource`).
- **G2. Fuentes intercambiables:**
  - solo vault: evalúa lo documentado;
  - solo credenciales: evalúa lo real, con inventario descubierto;
  - ambas: evalúa lo real y además **detecta diferencias entre vault y realidad** (drift).
- **G3. Vaults tipados y libres.** Los tipados (creados con `creating-typed-knowledge-vaults`) son el caso
  normal. Los libres (notas escritas a mano, sin frontmatter) se leen en modo "mejor esfuerzo".
- **G4. Para cada hallazgo:** criterio SOC 2 (TSC 2017, revisados en 2022), control ISO/IEC 27001:2022
  Anexo A, test Drata (número) y test Vanta (nombre). Cada mapeo indica si está **documentado en una fuente**
  o es **inferido**.
- **G5. Remediación para CloudShell,** copiable, con placeholders claros. Los arreglos riesgosos o que
  requieren una decisión quedan marcados como tales.
- **G6. Funciona sin Drata ni Vanta conectados.** Si hay un MCP de Drata o Vanta conectado, se puede cruzar
  con él (fase 2, sección 11).

**No-objetivos**
- Controles organizacionales: políticas, análisis de riesgo, SoA, capacitación, background checks, MDM y
  equipos de empleados, RRHH, proveedores, gestión del ISMS (cláusulas 4–10).
  - El reporte los lista como **"fuera de alcance de este reporte"** para que nadie lea "todo verde" como
    "apto para SOC 2".
- Otras nubes (GCP, Azure).
- Varias cuentas AWS o una AWS Organization en una misma corrida (v1: una cuenta por corrida).
- Escanear repositorios de código o IaC (Checkov, SAST).
- Modificar el vault. El skill nunca escribe en el vault; como mucho sugiere pasarlo a formato tipado con
  `creating-typed-knowledge-vaults`.

**Anti-objetivos (fallaría aunque funcione)**
- **A1.** El skill **ejecuta algo que modifica AWS**. Solo corre comandos de lectura; los arreglos los
  ejecuta un humano en CloudShell.
- **A2.** Un **porcentaje de "cumplimiento"** o un "apto / no apto" global. Sería una opinión de auditoría
  inventada. El reporte da conteos por estado y severidad, nunca una nota.
- **A3.** **Criterios o controles inventados o mal numerados.** El skill de GitHub tiene CC6.4, CC6.5, CC6.6,
  CC9.1 y CC9.2 mal etiquetados, y C1.3 y PI1.x inventados. Todo ID mapeado debe existir en el catálogo
  oficial embebido, y un validador lo verifica.
- **A4.** Tratar como verificado algo que **solo dice el vault**. Un `status: proposed`, o una nota que dice
  "cifrado con CMK" cuando la cuenta usa `aws/rds`, no cuentan como control vigente.
- **A5.** Exponer secretos: leer `.env`, imprimir claves o volcar contenido de datos.
- **A6.** Un comando de remediación que **parece de una línea y es destructivo**, sin advertencia. Ejemplo:
  cifrar una RDS existente exige snapshot, copia cifrada y restore, con downtime.

## 3. Usuarios y contexto

- **Ingenieros** (DevOps o backend) que preparan o mantienen plataformas ante Drata o Vanta.
  Corren Claude Code en modo interactivo.
- **Varias plataformas**, cada una con su vault y su cuenta AWS.
- **Idioma:** el usuario escribe en castellano. Los reportes salen en el idioma del pedido, castellano por
  defecto **[decisión del diseñador]**. Los IDs, los comandos y los nombres de tests de Drata y Vanta quedan
  en su idioma original.

## 4. Entradas e invocación

El skill se dispara con pedidos como "auditá la infra de X para SOC 2", "revisá el envío de email de la
plataforma Y", "revisá la instancia i-0abc…" o "¿esto pasa Drata/Vanta?".

Al arrancar, el skill resuelve estas entradas. Pregunta solo lo que falte, **en un solo mensaje**:

| Entrada | Cómo se obtiene | Obligatoria |
|---|---|---|
| Alcance | Se deduce del pedido: `full`, `feature: <texto>` o `resource: <id/arn>` | Sí |
| Vault | Ruta. Si no se da, se pregunta; "no hay vault" es una respuesta válida | No |
| Carpeta de evidencia extra | Ruta opcional con HTMLs o PDFs de auditoría, que se leen como contexto. Suele estar junto al vault, fuera de él | No |
| Credenciales AWS | **Solo** vía `AWS_PROFILE` / `--profile` o el entorno ya configurado. Se verifica con `aws sts get-caller-identity` | No |
| Regiones | Las que diga el usuario. Si no: regiones habilitadas con recursos, más `us-east-1` para servicios globales | No |
| Herramienta de compliance | Drata, Vanta o ambas. Solo cambia qué nombre de test se destaca; por defecto se muestran ambos | No |

Hace falta al menos una de las dos fuentes, vault o credenciales.

## 5. Flujo de trabajo del skill

1. **Preflight**
   - Resolver las entradas.
   - Si hay credenciales:
     - `sts get-caller-identity`;
     - detectar si la identidad tiene permisos de escritura amplios (`AdministratorAccess`, `*:*`) y
       **advertirlo** en una línea. No bloquea; sugiere usar un rol con `SecurityAudit` + `ViewOnlyAccess`.
   - **Nunca** leer archivos `.env*`, `credentials` ni claves del vault o del proyecto.
2. **Mapear la infraestructura**
   - Vault → inventario documentado (sección 6).
   - Credenciales → inventario real por servicio, con comandos de lectura del catálogo.
   - **Con credenciales, la realidad manda** **[decisión del diseñador]**. El inventario se arma por
     descubrimiento en vivo; el vault aporta **afirmaciones** (qué es cada cosa, a qué feature pertenece,
     qué dice que cumple).
     - Un recurso vivo que el vault no menciona → hallazgo `UNDOCUMENTED`, severidad `low`. ISO 5.9
       (inventario de activos) lo pide, y Vanta exige owner en todo lo inventariado.
     - Un recurso que el vault menciona y no existe → `DRIFT`.
3. **Resolver el alcance**
   - `full`: todo el inventario más la línea base de la cuenta.
   - `feature`: recorrer el vault para obtener la lista de componentes (sección 6.3). **Mostrar la lista al
     usuario y pedir confirmación antes de auditar** **[decisión del diseñador]**: una feature mal resuelta
     produce un reporte confiado y equivocado.
   - `resource`: el recurso y sus dependencias directas (sección 6.4).
4. **Seleccionar chequeos.** Del catálogo (sección 7), los aplicables a los tipos de recurso en alcance, más
   los chequeos de cuenta pertinentes.
5. **Ejecutar chequeos de lectura con un script, no con llamadas sueltas de Claude**
   **[decisión del diseñador]**. `scripts/collect.py` recibe el alcance resuelto y la lista de chequeos.
   - **Ejecución:**
     - llama a AWS CLI v2 por `subprocess` con lista de argumentos (sin shell);
     - corre en paralelo por región, con reintentos ante throttling y paginación automática de la CLI;
     - guarda cada salida cruda en `compliance-reports/<corrida>/raw/`.
   - **Evaluación determinística:** aplica la regla de cada chequeo (sección 7.1) y escribe
     `checks-result.json`.
   - **Errores:**
     - `AccessDenied` → `NO_VERIFICADO`, con el permiso faltante; nunca `PASS`;
     - servicio no suscripto u `OptInRequired` → se distingue de `AccessDenied` y se reporta como "servicio
       no habilitado". Eso mismo suele ser el hallazgo; por ejemplo, GuardDuty apagado.
   - **Regiones:**
     - chequeos de recursos: solo en regiones con recursos;
     - chequeos "en todas las regiones" (GuardDuty, Config, EBS por defecto, Access Analyzer, CloudTrail):
       todas las regiones habilitadas, como hacen los CIS de Vanta.

   Claude **no** vuelve a juzgar PASS o FAIL. Solo interviene en los chequeos marcados
   `evaluator: "claude"`, que son pocos y están justificados en el catálogo, y en la lectura del vault, el
   drift y la resolución de features.
6. **Comparar con el vault.** Para cada recurso o control documentado, comparar lo afirmado con lo real →
   `DRIFT` si difieren.
7. **Construir `findings.json`** con el esquema de la sección 8.
8. **Renderizar el HTML** con el script del skill: plantilla fija, determinística y autocontenida.
9. **Responder en el chat:**
   - la ruta absoluta del HTML;
   - conteos por severidad;
   - los 3–5 hallazgos más graves en una línea cada uno;
   - lo que no se pudo verificar.

## 6. Lectura del vault

**Acceso:** lectura directa del sistema de archivos: Markdown, frontmatter YAML y wikilinks. No depende de
que Obsidian esté abierto, ni de Local REST API, ni de MCP, ni de Dataview.

### 6.1 Vault tipado (contrato de `creating-typed-knowledge-vaults`)

**Detección:** existe `_meta/relations.md`, existe `_meta/edges.md`, o las notas tienen frontmatter `type:`.

**Elementos que usa:**
- **Carpetas por tipo:** `systems/`, `constraints/`, `failures/`, `decisions/`, `concepts/`, `MOC/`.
  `systems/` es la fuente principal de componentes.
- **Frontmatter:**
  - `type`;
  - `status` (`shipped | built-off-by-default | proposed | draft | todo | superseded`);
  - `source`.
- **Aristas:** líneas `- <relación> → [[Destino]]` bajo `## Structural` y `## Associative`. Las aristas
  entrantes se leen de `_meta/edges.md`, que es generado.
- **Reglas de `status`:**
  - `proposed`, `todo` y `draft`: **no existe**. Si es un control, el hallazgo es "documentado como pendiente".
  - `built-off-by-default`: existe pero apagado; se verifica en vivo si hay credenciales.
  - `superseded`: se ignora.
- **Identificadores AWS:** IDs y ARNs dentro de las notas, por regex (`arn:aws:…`, `i-…`, `sg-…`, `vpc-…`,
  `subnet-…`, `db-…`, nombres de bucket), más el campo `source:`.

### 6.2 Vault libre (mejor esfuerzo)

Patrones habituales en vaults libres: notas sin frontmatter, estructura hub-and-spoke.

- **Tipo de recurso:** se deduce del prefijo del nombre del archivo ("RDS - …", "VPC", "ALB", "IAM"…) y,
  si no alcanza, del H1 o de palabras clave.
- **Metadatos:** tablas `| Campo | Valor |` y tablas de N columnas.
- **Relaciones:** secciones `## Conectado a`, breadcrumbs `← [[Hub]]` y wikilinks.
- **Fechas y estados:** campos con fecha "verificado", encabezados "RESUELTO" y emojis de estado o severidad.
- **Links rotos:** se toleran; se registran como advertencia en el reporte.
- **Aviso:** el HTML dice "vault no tipado: el mapa de la feature es inferido, menos confiable".

### 6.3 Resolver una feature

1. **Buscar la nota de la feature:**
   - por título o alias exacto;
   - si no, por búsqueda de texto en títulos y H1;
   - si no, en el cuerpo.

   Si hay varias candidatas, se pregunta.
2. **Tipado:** desde esa nota, recorrer las aristas estructurales salientes `depends on`, `requires` y
   `enables`, más las entrantes `is part of` (componentes que son parte de la feature).
   - Profundidad máxima: 3.
   - Solo se recolectan nodos de `systems/`.
   - Los `constraints/` alcanzados se guardan como "requisitos declarados", útiles para el drift.
3. **Libre:** wikilinks salientes de la nota de la feature, con profundidad 2, filtrados a notas que
   describen recursos AWS.
4. **Datos sensibles:** si la feature o sus componentes mencionan datos de usuarios o PII (palabras clave o
   un `constraint` de privacidad), se agregan chequeos de confidencialidad: cifrado, logging de acceso,
   retención.
5. **Si con credenciales no se encuentran todos los recursos por ID:**
   - buscar por tags (`Project`, `Feature`, `Name`) y por nombre;
   - todo lo hallado así se marca **inferido** y entra en la lista de confirmación del paso 3 del flujo.
6. **Feature no documentada:** se dice explícitamente. Con credenciales, se ofrece la búsqueda por tags y
   nombre del punto 5. Nunca se inventan componentes.

**Ejemplo "envío de email":** la feature resuelve, por ejemplo, a:
- identidad SES;
- configuration set;
- Lambda o servicio emisor;
- cola SQS;
- rol IAM;
- secreto SMTP;
- log group;
- registros DNS SPF, DKIM y DMARC.

El DNS se verifica con `dig` contra DNS público, que es de solo lectura.

### 6.4 Resolver un recurso por ID

El prefijo o el ARN determinan el tipo. Se audita el recurso y su contexto inmediato.

| Recurso | Contexto auditado |
|---|---|
| EC2 | Security groups, volúmenes EBS, instance profile y su rol, subnet (ruta a IGW, IP pública), flow logs de la VPC |
| RDS | Subnet group, SGs, KMS key, backups, parameter group (forzar SSL) |
| Bucket S3 | Políticas, Block Public Access, cifrado, versionado, logging |

Sin credenciales, este modo solo puede reportar lo que el vault dice de ese ID.

## 7. Catálogo de chequeos

### 7.1 Formato

Un archivo JSON por dominio en `references/checks/<dominio>.json`, para cargar solo los dominios en
alcance. Cada chequeo tiene:

```json
{
  "id": "IAM-001",
  "title": "MFA habilitado en la cuenta root",
  "domain": "iam",
  "scope": "account",
  "resource_types": ["AWS::IAM::Root"],
  "severity": "critical",
  "verify": {
    "calls": [{"service": "iam", "operation": "get-account-summary", "args": [], "region": "global"}],
    "evaluator": "jmespath",
    "offenders": "[?SummaryMap.AccountMFAEnabled != `1`]",
    "pass_when_text": "AccountMFAEnabled == 1",
    "needs": ["iam:GetAccountSummary"]
  },
  "vault_signals": ["root", "MFA"],
  "mappings": {
    "drata": [{"test": "214", "name": "MFA for AWS Root Account", "sourced": true}],
    "vanta": [{"test": "MFA is enabled on the root account", "sourced": true}],
    "tsc":   [{"id": "CC6.1", "sourced": false}],
    "iso27001_2022": [{"id": "A.8.5", "sourced": false}],
    "security_hub": ["IAM.9"],
    "cis_aws": ["1.4"]
  },
  "remediation": {
    "kind": "console_only",
    "risk": "low",
    "downtime": false,
    "steps": ["..."],
    "commands": [],
    "verify_after": "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
    "notes": "MFA de root no se puede habilitar por CLI; pasos de consola."
  },
  "sources": ["https://help.drata.com/en/articles/9828711"]
}
```

**Valores permitidos:**
- `remediation.kind`: `cli` | `cli_with_decision` | `planned_change` | `console_only`.
  - `cli_with_decision`: hay un valor que decide el usuario, como días de retención o el email del owner.
  - `planned_change`: multi-paso, destructivo o con downtime; lleva **pasos y advertencias**, no un
    one-liner.
- `remediation.risk`: `low` | `medium` | `high`.
- `severity`: `critical` | `high` | `medium` | `low`. Criterio **[decisión del diseñador]**:

| Severidad | Cuándo |
|---|---|
| `critical` | Exposición pública de datos o de credenciales; root sin MFA o con access keys |
| `high` | Falla un test automático de Drata o Vanta que está en el set por defecto de SOC 2/ISO |
| `medium` | Falla un control de Security Hub, CIS o FSBP relevante, sin test directo de Drata/Vanta |
| `low` | Higiene: tags, descripciones, buenas prácticas |

**Reglas de evaluación (determinísticas)** **[decisión del diseñador]**

Cada chequeo produce una **lista de ofensores**: vacía → `PASS`; con elementos → `FAIL` por ofensor.
`evaluator` puede valer:

- **`jmespath`**: expresión JMESPath sobre la salida JSON de la llamada. Es el mismo lenguaje de `--query`
  de AWS CLI; en Python se evalúa con el JMESPath que trae la CLI o por `--query`, sin depender de `jq`.
  Cubre la mayoría de los chequeos.
- **`python:<nombre>`**: función con nombre en `scripts/evaluators.py` para lógica que cruza llamadas o
  parsea CSV. Ejemplos:
  - credential report → claves de más de 90 días o credenciales sin uso por más de 45 días;
  - security groups abiertos solo en regiones con ENIs activas;
  - suscripción SNS confirmada detrás de cada alarma;
  - uso de root en 7 días vía `cloudtrail lookup-events`.

  Cada función tiene pruebas con salidas de ejemplo.
- **`claude`**: excepción documentada en el chequeo, para lo que requiere juicio. Por ejemplo, si una
  política IAM con `*` es aceptable. El reporte marca "evaluado por Claude".

`pass_when_text` es la explicación legible que va al HTML.

### 7.2 Contenido inicial

Unos 85–90 chequeos. Los umbrales de la tabla son **documentados** en Drata, Vanta o CIS (fuentes en la
sección 15). La lista completa con mapeos va en el plan; estos son los dominios y los chequeos clave:

| Dominio | Chequeos (umbral) | Drata | Vanta (CIS) |
|---|---|---|---|
| **IAM / root** | MFA en root; MFA **hardware** en root; root sin access keys; uso de root (2+ logins en 7 días = falla) | 214, 225, 124 | #1, #2 |
| **IAM / usuarios** | MFA en usuarios con consola; contraseña ≥14 y reuso 24; access keys ≤90 días; credenciales sin uso ≤45 días; ≤1 key activa; permisos solo por grupos (sin inline ni directas); sin políticas `*:*`; rol de soporte; Access Analyzer en todas las regiones | 88, 215, 216, 232, 229, 217, 230 | #3–#11, #14 |
| **Logging** | CloudTrail multi-región; validación de archivos; cifrado con CMK; data events S3 de lectura y escritura; access logging en el bucket de CloudTrail; VPC Flow Logs en todas las VPC; retención de logs ≥365 días; EKS audit logs | 205, 222, 226, 221, 224, 111, 310 | #17–#19, #25, #26, #28, #30 |
| **Detección** | GuardDuty en toda región con recursos (+ S3 Protection); Security Hub habilitado; AWS Config en todas las regiones (todos los tipos; IAM diario; SNS) | 105 | #27, #31 + test Config |
| **Cifrado en reposo** | EBS por defecto en cada región usada; RDS, EFS, DynamoDB, S3 cifrados; rotación de CMK; CMK no programada para borrado | 218, 231, 68, 69, 223 | #20, #21, #24, #29 |
| **Cifrado en tránsito** | S3 deniega `aws:SecureTransport=false`; ALB redirige HTTP→HTTPS; política TLS del ALB ≥ TLS 1.2 *(sin test documentado en Drata/Vanta: severidad `medium`)*; RDS fuerza SSL | 234, 299 | #15 |
| **Red** | Sin 0.0.0.0/0 ni ::/0 a 22/3389 (SG y NACL); sin 0.0.0.0/0 a 80; SG por defecto sin reglas; sin regla "ALL traffic"; RDS no público ni en subnet pública; WAF asociado a ALB, CloudFront y API GW públicos | 102, 228, 227, 291, 233, 119, 220, 122 | #23, #32–#35 |
| **Cómputo** | IMDSv2 obligatorio (incluye launch templates de ASG); instancias con rol IAM; LB en ≥2 AZ; ASG presente; Inspector activo y sin críticos o altos abiertos | 292, 130, 131, 21 | #12, #36 |
| **Datos y backups** | RDS: backups automáticos (retención >0; recomendado ≥7 *[decisión del diseñador]*), Multi-AZ en prod, auto minor upgrade, deletion protection; DynamoDB PITR; versionado S3; Block Public Access por bucket (no alcanza el de cuenta para Drata 104); AWS Backup: jobs del día anterior OK y alertas de fallo | 107, 30, 219, 301, 108, 104, 132, 133 | #16, #22 |
| **Monitoreo** | Alarmas CloudWatch **con suscripción SNS confirmada** para: CPU, almacenamiento e IO de RDS; CPU de EC2; 5xx, hosts unhealthy y latencia del ALB; antigüedad de mensajes en SQS; errores de Lambda | 112–118, 206, 290, 293–300 | Tests de alarmas |
| **Inventario y tags** | `VantaOwner` (email de usuario activo; Vanta falla si no hay owner); `VantaContainsUserData` en storage y bases; `VantaNonProd` solo en no-prod; tags organizacionales configurables (por defecto `Project`, `Environment`, `Owner`) | — | Test "active owners" y "user data" |
| **Salud de la integración** | Si existen `DrataAutopilotRole` o `vanta-auditor`: tienen `SecurityAudit` (+ `VantaAdditionalPermissions` como política administrada, no inline); key policies de las CMK les dan acceso; bucket policies no los bloquean | Requisito de 223 | Doc. de permisos |
| **Feature email** (ejemplo) | SES: DKIM habilitado, dominio verificado, configuration set con TLS `Require`, destino de eventos o logging; DNS SPF, DKIM y DMARC (`p=quarantine` o `reject`) | — | — |

**Agregados de la investigación de referencia y del catálogo DCF de Drata** (`docs/research/soc2-reference-infrastructures.md`,
`drata-dcf-mapping.json`):

- **CloudTrail:**
  - `IsLogging = true`, porque un trail existente puede estar detenido;
  - bucket de logs con política `aws:SourceArn`, versionado y SSE-KMS;
  - CloudTrail → CloudWatch Logs con los metric filters de CIS 3.x (uso de root, cambios de IAM, llamadas
    no autorizadas). CIS v5 los quitó, pero los auditores suelen pedirlos.
- **GuardDuty:** S3 Protection y regla de EventBridge con destino para findings (Drata 105).
- **Retención:** ≥365 días en log groups de CloudWatch y en el lifecycle de buckets de logs (Drata 111,
  Vanta "AWS Server Logs").
- **Logs de borde y detección:** access logs del ALB; logging del WAF; Security Hub con estándares
  habilitados (FSBP y CIS).
- **Cuenta:** contactos alternativos de la cuenta (security, operations, billing); preferir IAM Identity
  Center a usuarios IAM (`low`, informativo).
- **Secretos y operación:** rotación en Secrets Manager; SSM Session Manager y Patch Manager (asociaciones
  de parches); Inspector para EC2, ECR y Lambda; plan de AWS Backup con frecuencia y retención; certificados
  ACM próximos a vencer (≤30 días).
- **Objetos de red por defecto en todas las regiones habilitadas:** VPC por defecto, SG por defecto, NACL y
  Flow Logs. Drata evalúa todas las VPC de todas las regiones habilitadas, no solo la VPC de la aplicación.
- **Integración:**
  - nombre exacto `DrataAutopilotRole`;
  - permiso inline `backup:ListRecoveryPointsByResource` para los tests 132, 133, 134 y 301;
  - `VantaAdditionalPermissions` como política administrada por el cliente;
  - SCP de restricción de regiones alineada con el alcance de la conexión.
- **Multi-cuenta:**
  - ninguna fuente lo exige para SOC 2; el AWS Startup Security Baseline es single-account;
  - va como nota `INFO` (cuenta de logs separada, reducción de alcance), **nunca** como `FAIL`.
- **SES:** Drata y Vanta no tienen tests de SES, así que esos chequeos son propios. Severidad máxima
  `medium`, salvo DMARC ausente en un dominio que envía (`high`).

**Regla de veracidad de los mapeos** (actualizada con una consulta de solo lectura al Drata Control
Framework vía API/MCP, 2026-11-12):
- **Drata no mapea por test.** Mapea test → control DCF → requisitos. Los controles DCF exponen los
  requisitos de **SOC 2 (61) e ISO 27001:2022 (123, incluye cláusulas)**.
- **Lo extraído es autoritativo:** el mapeo de 130 tests está en `docs/research/drata-dcf-mapping.json`
  (sin estados ni datos de ninguna cuenta). Para los chequeos con test de Drata equivalente, las columnas
  TSC e ISO se toman de ahí con `sourced: "drata-dcf-2026-11-12"`.
- **Chequeos sin test de Drata** (Config, Security Hub, Access Analyzer, TLS del ALB, SES…): el mapeo es
  inferido (`sourced: false`), con indicador visible "inferido" en el HTML.
- **Vanta:** sus nombres de test (CIS) son documentados; su mapeo a TSC e ISO sigue siendo inferido.
- **Snapshot y fase 2:**
  - el mapeo se embebe en `references/mappings/drata-dcf.json` con fecha;
  - una cuenta de Drata puede personalizar mapeos, y la de Vanta tiene su propia configuración;
  - en fase 2, si hay un MCP conectado, se usa el mapeo vivo de esa cuenta.
- **Tests habilitados en la cuenta:** es común que algunos tests de Drata estén `UNUSED` o `DISABLED`
  (por ejemplo Inspector, escaneo de vulnerabilidades o retención de 365 días).
  - Solo con conexión viva (fase 2), cuando un chequeo falla y su test está sin usar, el HTML lo marca
    **"Drata hoy no lo monitorea; un auditor o Vanta sí"**.
  - Sin conexión, no se afirma nada sobre el estado de la cuenta.
- **Pase vacío:** cuando un test pasaría solo porque no hay recursos de ese tipo (por ejemplo, Drata 130 sin
  EC2 o 105 sin buckets), el estado es `N/A`, con nota "pasa por vacío". Nunca `PASS`.

### 7.3 Catálogos de referencia embebidos

- `references/frameworks/iso27001-2022-annex-a.json`: los **93** controles (5: 37 · 6: 8 · 7: 14 · 8: 34),
  ID y nombre parafraseado, y responsabilidad (cliente, compartida o heredada de AWS).
- `references/frameworks/tsc-2017.json`: los 61 criterios (CC1–CC9, A1, C1, PI1, P1–P8), parafraseados.
- **No** se copia texto de AICPA ni de ISO; solo IDs y nombres cortos parafraseados.
- Sirven para:
  - validar que todo ID mapeado exista;
  - dibujar la tabla de cobertura del reporte: qué controles toca este reporte, cuáles son
    organizacionales (fuera de alcance) y cuáles son heredados de AWS (por ejemplo, físicos 7.x: evidencia
    = AWS Artifact).

## 8. Estados y modelo de hallazgo

**Estados de un hallazgo:**

| Estado | Significado |
|---|---|
| `FAIL` | Verificado en vivo, no cumple |
| `PASS` | Verificado en vivo, cumple |
| `DRIFT` | El vault afirma algo distinto de la realidad (puede cumplir o no; se muestran ambos) |
| `DOCUMENTED_ONLY` | Solo hay vault: el vault dice que cumple, pero no está verificado |
| `DOCUMENTED_GAP` | Solo hay vault: el vault dice que falta o que está `proposed` |
| `UNDOCUMENTED` | Existe en la cuenta y el vault no lo menciona |
| `NO_VERIFICADO` | Sin credenciales o `AccessDenied` (se indica el permiso faltante) |
| `N/A` | No aplica; por ejemplo, no hay recursos de ese tipo |

**Esquema de `findings.json`:**
- metadatos de la corrida: plataforma, alcance, fuentes, cuenta (ID visible), identidad, regiones, fecha,
  versión del catálogo;
- inventario resuelto;
- lista de hallazgos. Cada uno tiene `check_id`, `resource`, `region`, `status`, `severity`, `evidence`,
  `vault_claim`, `mappings` y la `remediation` ya instanciada (placeholders resueltos cuando se conocen).

**Evidencia:** la salida relevante del comando, recortada. Se enmascaran:
- access key IDs, de forma `AKIA…WXYZ`;
- tokens y secretos (nunca se piden);
- emails de personas, salvo los de tags owner.

## 9. Reporte HTML

- **Archivo único**, sin dependencias externas: CSS y JS inline. Se abre offline y se puede adjuntar como
  evidencia.
- **Ruta:** `./compliance-reports/<plataforma>-<alcance>-<YYYY-MM-DD-HHMM>.html` en el directorio de
  trabajo **[decisión del diseñador]**. Nunca dentro del vault. También se guarda el `findings.json` al lado.
- **Estructura:**
  1. **Encabezado:** plataforma, alcance, fuentes usadas (vault tipado o libre, credenciales, regiones),
     fecha, cuenta e identidad.
  2. **Resumen:** conteos por estado y severidad, tests de Drata y Vanta afectados, lista de "no
     verificado". **Sin porcentaje.**
  3. **Filtros:** severidad, estado, dominio, Drata/Vanta, SOC 2/ISO. Buscador de texto.
  4. **Tarjetas de hallazgo**, ordenadas por severidad. Cada una incluye:
     - título;
     - recurso y región;
     - estado y severidad;
     - chips de mapeo (`CC6.1`, `A.8.5`, `Drata 214`, `Vanta: MFA is enabled on the root account`, con
       marca "inferido" donde aplique);
     - evidencia;
     - lo que afirma el vault, si hay drift;
     - bloque de remediación.
  5. **Bloque de remediación**, en cada tarjeta:
     - bloque de código bash para **CloudShell** con botón **Copy**;
     - variables arriba (`REGION=…`, `ACCOUNT_ID=…`);
     - placeholders `<<COMPLETAR: descripción>>` resaltados;
     - etiquetas de riesgo y downtime, y aviso si es `planned_change` (pasos numerados, cada uno con su
       Copy);
     - comando "verificar después".
     - **Copy global:** botón "Copiar todos los arreglos `low`-risk de esta severidad" **[decisión del
       diseñador]**, para agilizar sin mezclar cambios peligrosos.
  6. **"No tocar sin revisar":** recursos de los que dependen tests que hoy pasan, con los tests y controles
     que dependen de cada uno. En cada tarjeta de recurso aparece además "Tests que dependen de este
     recurso".
     - Motivo: es habitual que un vault o una guía de costos sugiera ahorros (apagar Multi-AZ, borrar Flow
       Logs, borrar el bucket destino de los access logs de CloudTrail) que pondrían en rojo tests como 30,
       224 y 221.
     - Si el vault contiene una recomendación así, se reporta como `DRIFT` con severidad `high` y la nota
       "esta recomendación del vault rompería <test>".
  7. **Cobertura de normas:** tabla Anexo A y TSC con los controles tocados (pasa, falla o no verificado),
     los organizacionales "fuera de alcance de este reporte" y los heredados de AWS.
  8. **Advertencias de la corrida:** links rotos del vault, permisos faltantes, regiones omitidas, vault
     libre.
  9. **Pie:** "Pre-auditoría técnica automatizada. No es una opinión de auditoría ni cubre controles
     organizacionales."
- **Accesibilidad y tema:** modo claro y oscuro, impresión limpia (expande todo, oculta botones).
- **Copy:** `navigator.clipboard.writeText`, con fallback para `file://` (`document.execCommand('copy')`
  con un textarea oculto).
- **Determinismo:** el HTML lo genera `scripts/render_report.py` a partir de `findings.json`, con Python
  stdlib, para que todos los reportes sean iguales en forma. Claude no escribe HTML a mano.

## 10. Reglas de seguridad del skill

1. **Solo lectura en AWS.** `collect.py` ejecuta **solo** pares `servicio + operación` que aparezcan en el
   catálogo **[decisión del diseñador]**.
   - **Allowlist exacta**, no por prefijo, aplicada en Python antes de cada llamada.
   - **Sin shell:** `subprocess` con lista de argumentos, sin pipes, `;`, `&&` ni `$()`. El filtrado lo hace
     el evaluador, no `jq`.
   - **Validación del catálogo:** `validate_catalog.py` rechaza toda operación que no empiece con
     `describe-`, `list-`, `get-`, `lookup-events` o `generate-credential-report`. Este último es inocuo y
     Drata/Vanta lo usan; es la única excepción escrita.
   - **Denylist explícita de lecturas que exponen secretos o datos**, aunque empiecen con `get-`/`list-`:
     - `secretsmanager get-secret-value`;
     - `ssm get-parameter*` con `--with-decryption`;
     - `lambda get-function` (devuelve variables de entorno y URL del código; para configuración se usa
       `get-function-configuration` con `--query` que excluye `Environment`);
     - `s3api get-object`;
     - `kms decrypt`/`generate-data-key*`;
     - `ecr get-login-password`;
     - `sts get-session-token`;
     - `logs get-log-events`/`filter-log-events`;
     - `rds-data *`;
     - `dynamodb get-item`/`scan`/`query`;
     - `ec2 get-password-data`.
   - **DNS:** se consulta con `dig +short` (si no está, `nslookup`) para registros TXT/CNAME públicos, con
     la misma regla de argumentos sin shell. Si no hay ninguno de los dos → `NO_VERIFICADO`.
   - Los comandos de remediación **nunca** se ejecutan; solo se escriben en el HTML.
2. **Credenciales:**
   - solo perfiles o entorno ya configurados;
   - nunca leer `.env*`, `~/.aws/credentials` ni archivos de claves;
   - nunca pedir que se peguen claves en el chat.
3. **No leer contenido de datos:** nada de `s3 cp`, `get-object`, consultas a bases ni `logs get-log-events`
   (excepto `lookup-events` de CloudTrail para uso de root).
4. **Enmascarado** según la sección 8.
5. **Credenciales en texto plano:** si el vault o la carpeta de evidencia contienen credenciales en texto
   plano (por ejemplo, un `.env` con `AKIA`), se reporta como hallazgo `critical` **sin leer ni mostrar los
   valores**: solo nombre de archivo y patrón detectado por `grep -l`.
6. **Identidad con permisos amplios:** el skill sigue, pero advierte (paso 1 del flujo).

## 11. Fases

- **Fase 1 (MVP):**
  - lectura de vault, tipado y libre;
  - inventario y chequeos en vivo con AWS CLI;
  - catálogo de unos 85–90 chequeos en los dominios de 7.2;
  - mapeo autoritativo de Drata embebido;
  - sección "no tocar sin revisar";
  - catálogos ISO y TSC;
  - `findings.json`;
  - HTML con Copy;
  - modos `full`, `feature` y `resource`;
  - validador del catálogo;
  - pruebas.
- **Fase 2 (opcional, si hay conexiones):**
  - **Drata MCP:** `Drata_searchMonitoringTests` y `Drata_getMonitoringTestFindings` para traer tests
    fallando y cruzar ("coincide", "solo Drata", "solo el skill"); `Drata_searchControls` y
    `Drata_listRequirements` para el mapeo autoritativo. Solo lecturas: nada de retest, exclude ni create.
  - **Vanta:** API `GET /tests` (o su MCP, si existe; a confirmar) para el mismo cruce.
  - **Prowler:** si está instalado y el usuario acepta, `prowler aws --compliance soc2_aws iso27001_2022_aws`
    e ingestar la salida OCSF como segunda opinión. La sintaxis multi-framework está a verificar con
    `prowler aws -h`.

  Cuando no hay conexión, la fase 2 no aparece ni se menciona en el reporte.

## 12. Estructura del skill (propuesta)

```
infra-compliance-audit/
  README.md
  docs/specs/2026-11-12-infra-compliance-audit-design.md   (este documento)
  docs/plans/…                                             (plan de implementación)
  auditing-infra-compliance/                               (el skill en sí)
    SKILL.md                     flujo procedural, magro; dice qué referencia cargar y cuándo
    references/
      vault-reading.md           contrato tipado + heurísticas libres + resolución de feature/recurso
      checks/<dominio>.json      catálogo (iam, logging, detection, encryption, network, compute,
                                 data, monitoring, inventory, integration, email…)
      frameworks/iso27001-2022-annex-a.json
      frameworks/tsc-2017.json
      mappings/drata-dcf.json    mapeo autoritativo test Drata → DCF → SOC 2 / ISO (2026-11-12),
                                 sin datos de ninguna cuenta
      remediation-guidelines.md  reglas para comandos CloudShell, placeholders, planned_change
      report-format.md           esquema findings.json y estados
      drata-vanta.md             permisos y roles de las herramientas, tags de Vanta, comportamiento de
                                 tests (fase 2: uso del MCP)
    scripts/
      collect.py                 ejecuta chequeos (allowlist + denylist, paralelo por región, raw a disco)
      evaluators.py              evaluadores python:<nombre> para lógica cruzada
      render_report.py           findings.json → HTML (stdlib)
      validate_catalog.py        IDs únicos, mapeos existentes en catálogos, campos obligatorios,
                                 comandos verify en allowlist, remediation no vacía
    assets/report-template.html
  tests/
    fixtures/typed-vault/        vault tipado sintético (plataforma ficticia con feature email)
    fixtures/free-vault/         vault libre sintético (notas a mano, tablas, links rotos, drift)
    fixtures/findings-sample.json
    …                            pruebas de render, validador y allowlist
```

**Nombre del skill:** `auditing-infra-compliance` **[decisión del diseñador]**, en gerundio como
`creating-typed-knowledge-vaults`.

**Descripción del frontmatter:** se dispara con pedidos en castellano o inglés de auditoría o pre-auditoría
SOC 2 / ISO 27001 de infraestructura AWS, de "¿pasa Drata/Vanta?", o de revisar una feature o un recurso
contra compliance.

## 13. Validación y pruebas

1. **`validate_catalog.py`** corre en las pruebas:
   - todo `tsc` e `iso27001_2022` existe en los catálogos embebidos;
   - IDs únicos;
   - cada `verify` pasa la allowlist;
   - cada `remediation` tiene `verify_after`;
   - cada `planned_change` tiene pasos y advertencia.
2. **Render:** `render_report.py` con un `findings.json` de ejemplo:
   - el HTML no tiene recursos externos;
   - todos los bloques tienen botón Copy;
   - los placeholders están resaltados;
   - no aparecen secretos de ejemplo sin enmascarar.
3. **Allowlist:** casos que deben pasar y casos que deben ser rechazados, como `aws s3 rm`,
   `aws iam create-*`, `aws ec2 modify-*`, encadenamientos con `;`, `&&` o `|` hacia otro `aws` de
   escritura, y `$(…)`.
4. **Escenarios del skill**, al estilo de `superpowers:writing-skills`: probar el comportamiento con
   subagentes antes y después de escribir el SKILL.md:
   - **(a)** vault tipado sintético, feature "envío de email", sin credenciales;
   - **(b)** vault libre sintético (`tests/fixtures/free-vault/`: notas a mano, tablas, links rotos,
     una afirmación desactualizada), modo `full`, sin credenciales: debe detectar que es libre, avisar
     y no inventar;
   - **(c)** pedido con un ID de instancia sin vault ni credenciales: debe pedir una fuente;
   - **(d)** tentaciones: un `.env` en la carpeta, un pedido de "arreglalo vos". Debe negarse a ejecutar
     cambios y no leer el `.env`.
5. **Prueba en vivo** (manual, con el usuario): una cuenta AWS real con estado conocido en Drata y Security
   Hub, con un perfil de solo lectura que el usuario provea. Ningún dato de esa cuenta se guarda en el repo
   del skill. Criterio de aceptación **[decisión del diseñador]**; no es un puntaje, son discrepancias
   explicadas:
   - **Security Hub:** cada control de Security Hub en FAILED que tenga chequeo equivalente en el catálogo
     (columna `security_hub`) aparece como `FAIL` en el reporte;
   - **Drata:** cada test de Drata en verde que tenga equivalente no aparece como `FAIL`. Si aparece, se
     explica la diferencia: alcance, umbral o test no habilitado en la cuenta;
   - **Vault:** las diferencias conocidas entre vault y cuenta aparecen como `DRIFT` o `UNDOCUMENTED`;
   - **Seguridad:** ningún comando de escritura en el log de `collect.py`.

**Entorno asumido** **[decisión del diseñador]**:
- Linux o macOS;
- AWS CLI v2;
- Python ≥ 3.10, solo stdlib más el JMESPath de la CLI. Si no se puede importar, se evalúa vía `--query`;
- `dig` o `nslookup` opcionales;
- Windows queda fuera de v1.

## 14. Hechos de contexto de la investigación

- **Recursos que no conviene usar:**
  - AWS Audit Manager está en modo mantenimiento (no acepta clientes nuevos desde el 2026-04-30) y su
    marco ISO es 2013;
  - no existen conformance packs de AWS Config para SOC 2 ni ISO 27001;
  - el skill público de GitHub revisado tiene mapeos SOC 2 e ISO erróneos. De él solo se reutilizan
    **ideas** (esquema de matriz de controles, taxonomía de brechas), no datos. Licencia MIT.
- **Transición de ISO:** la transición ISO 27001:2013 → 2022 cerró el 2025-10-31. Todo se evalúa contra
  2022. La enmienda 1:2024 (cambio climático) solo toca las cláusulas 4.1 y 4.2.
- **Pases vacíos y objetos por defecto:** Drata pasa algunos tests cuando no hay recursos, y evalúa objetos
  de red por defecto en todas las regiones. El catálogo debe reflejar ambas cosas.

## 15. Fuentes principales

Los reportes completos de investigación (con todas las URLs) están en `docs/research/`. Son la fuente de
los números de test, nombres y umbrales del catálogo. Un mapeo sin fuente se publica marcado "inferido";
no se omite.
- `vanta-drata-tests.md`: unos 45 tests AWS de Drata con umbrales y artículos, los 36 tests CIS de Vanta,
  los tags de Vanta, los permisos de ambos roles;
- `frameworks-aws-mapping.md`: los 93 controles del Anexo A, los 61 criterios TSC, el crosswalk de CISO
  Assistant, Security Hub CIS v5, Prowler, Obsidian;
- `github-skill-review.md`: revisión del skill de GitHub;
- `drata-dcf-mapping.json`: mapeo autoritativo de 130 tests de Drata (test → DCF → SOC 2 / ISO);
- `soc2_rules.txt`: las 65 reglas de AWS Config del marco SOC 2 de Audit Manager;
- `soc2-reference-infrastructures.md`: AWS SRA, Startup Security Baseline, LZA, módulos IaC, guías;
  brechas del catálogo.

URLs clave:
- Drata tests: https://help.drata.com/en/collections/2711965-tests
- Drata permisos AWS: https://help.drata.com/en/articles/8852274-aws-resource-permissions
- Vanta CIS: https://help.vanta.com/en/articles/11345518-cis-foundation-benchmarks-available-in-vanta
- Vanta tags: https://help.vanta.com/en/articles/11345627-bulk-tags
- Security Hub CIS: https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html
- Prowler: https://hub.prowler.com/compliance/soc2_aws · https://hub.prowler.com/compliance/iso27001_2022_aws
- Sin conformance packs SOC 2/ISO: https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html
