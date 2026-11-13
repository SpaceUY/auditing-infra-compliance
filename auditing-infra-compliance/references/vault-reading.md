# Lectura del vault

Se carga al tener vault o carpeta de evidencia, al resolver una feature o un recurso y al escribir claims. El skill **solo lee** el vault: nunca escribe en él.

## 1. Qué hace el indexador y qué queda fuera

`vault_index.py index` recorre el vault y escribe `vault-index.json` con, por nota: `path`, `title`, `type`, `status`, `source`, `aliases`, `edges` (relación, destino, capa), `links`, `parents`, `aws_ids`, `kv` (tablas de campos), `headings` e `inferred_type`. Más a nivel raíz: `kind` (`typed` | `free`), `broken_links`, `secrets_detected` (ruta y patrón, nunca el valor) y `obsidian_plugins` (solo nombres).

- Solo lee archivos `.md` regulares. Ignora todo archivo o carpeta que empiece con `.` (por eso **no ve** un `.env`), no sigue symlinks y no indexa `_meta/` como notas.
- Todo texto que entra al índice está enmascarado (claves `AKIA`/`ASIA`, secretos, emails).
- No abras `vault-index.json` entero en un vault grande: leé las notas que importan (Read sobre el `.md`) o filtrá con un `python3 -c` de solo lectura.

## 2. Vault tipado (contrato de `creating-typed-knowledge-vaults`)

Detección: existe `_meta/relations.md` o `_meta/edges.md`, o las notas tienen frontmatter `type:`.

| Elemento | Cómo se usa |
|---|---|
| Carpetas `systems/`, `constraints/`, `failures/`, `decisions/`, `concepts/`, `MOC/` | `systems/` es la fuente principal de componentes. `constraints/` son requisitos declarados (sirven para el drift). `failures/` y `decisions/` explican brechas y recomendaciones. |
| Frontmatter `type`, `status`, `source` | `source` apunta al repo o documento de origen; incluirlo en `vault_note` del claim cuando ayude. |
| Aristas `- <relación> → [[Destino]]` bajo `## Structural` y `## Associative` | Las entrantes están en `_meta/edges.md` (generado). |
| IDs y ARNs en el texto | `aws_ids` del índice (`arn:aws:…`, `i-…`, `sg-…`, `vpc-…`, `subnet-…`, `db-…`, etc.). Los nombres de bucket o de recursos sin prefijo hay que leerlos de la nota. |

### Qué significa `status`

| `status` en el vault | Tratamiento |
|---|---|
| `shipped` | Existe y está vigente; se compara con la realidad. |
| `built-off-by-default` | Existe pero apagado; con credenciales, verificar en vivo qué dice la cuenta. |
| `proposed`, `todo`, `draft` | **No existe.** Si es un control: `DOCUMENTED_GAP` ("documentado como pendiente"). Nunca contarlo como control vigente ni como `PASS`. En la lista de componentes de una feature se muestra marcado "pendiente (proposed)". |
| `superseded` | Se ignora. |

## 3. Vault libre (mejor esfuerzo)

Notas escritas a mano, sin frontmatter, estructura hub-and-spoke. Avisar siempre: **"vault no tipado: el mapa de la feature es inferido, menos confiable"**.

- **Tipo de recurso:** del prefijo del nombre del archivo ("RDS - …", "S3 - …", "ALB - …", "VPC", "IAM") y, si no alcanza, del H1 o de palabras clave (`inferred_type`).
- **Metadatos:** tablas `| Campo | Valor |` (`kv` en el índice): motor, identificador, cifrado, Multi-AZ, fecha de "Verificado".
- **Relaciones:** secciones `## Conectado a`, breadcrumbs `← [[Hub]]` y wikilinks.
- **Estados y fechas:** campos "Verificado: <fecha>", encabezados "RESUELTO", emojis de estado. Una fecha vieja = afirmación posiblemente desactualizada; decirlo, no darla por cierta.
- **Links rotos:** se toleran; ya salen como advertencias del reporte.
- No inventar componentes, relaciones ni estados que la nota no diga. Si una nota no basta para saber qué recurso es, el claim va como `DOCUMENTED_ONLY` con la duda en `vault_claim`, o se pregunta al usuario.

## 4. Resolver una feature

`vault_index.py feature <vault-index.json> "<texto>"` devuelve JSON con `candidates` (rutas), `chosen`, `components` (`path`, `title`, `via`, `depth`, `aws_ids`, `status`), `constraints`, `pii` y `confidence` (`typed` | `inferred`).

1. **Una nota candidata:** seguir. **Varias:** preguntar cuál. **Ninguna:** decir "esta feature no está documentada en el vault"; con credenciales ofrecer buscar por tags (`Project`, `Feature`, `Name`) y nombre, y marcar todo lo hallado así como **inferido**. Nunca inventar componentes.
2. Tipado: se recorren las aristas salientes `depends on`, `requires` y `enables` y las entrantes `is part of` (profundidad máxima 3), solo nodos de `systems/`. Libre: wikilinks salientes con profundidad 2, filtrados a notas que describen recursos AWS.
3. `pii: true` (la feature o sus componentes tocan datos de usuarios): decirlo en la confirmación y priorizar en el resumen los hallazgos de confidencialidad (cifrado, logging de acceso, retención) de los recursos del alcance.
4. **Mostrar al usuario y esperar confirmación**, con este formato:

```
Feature "envío de email" → nota systems/Email delivery.md (vault tipado)
  1. SES Identity        ses_identity    shipped    acme-notes.example
  2. Mailer Lambda       lambda_function shipped    acme-notes-mailer
  3. Mail Queue          sqs_queue       shipped    acme-notes-mail-queue
  4. Mailer Role         iam_role        shipped    acme-notes-mailer-role (profundidad 2)
  5. DMARC reject policy (sin recurso)   proposed   PENDIENTE: no existe todavía
Requisitos declarados: constraints/PII handling.md (hay datos personales)
¿Confirmás esta lista, o agrego/quito algo?
```

Los `proposed`/`todo`/`draft` se muestran pero **no se auditan como recursos vivos**: se reportan como `DOCUMENTED_GAP`.

## 5. Mapeo de `aws_ids` a tipos de inventario (`scope.json`)

El `type` de cada recurso del alcance es una clave de `references/inventory.json`. `id` puede ser el id, el nombre o el ARN del recurso tal como los lista el inventario (collect avisa con una advertencia "recurso del alcance sin coincidencia" si no calza).

| Señal en la nota | `type` | `id` a usar |
|---|---|---|
| `arn:aws:ses:…:identity/<dominio>` | `ses_identity` | el dominio o dirección (`acme-notes.example`) |
| `arn:aws:lambda:…:function:<n>` | `lambda_function` | el nombre de la función |
| `arn:aws:sqs:…:<n>` | `sqs_queue` | la URL de la cola (`https://sqs.<región>.amazonaws.com/<cuenta>/<n>`) |
| `arn:aws:sns:…:<n>` | `sns_topic` | el ARN |
| `arn:aws:iam::…:role/<n>` / `user/<n>` | `iam_role` / `iam_user` | el nombre |
| `arn:aws:kms:…:key/<id>` | `kms_key` | el ARN |
| `arn:aws:logs:…:log-group:<n>` | `log_group` | el nombre del log group |
| `arn:aws:secretsmanager:…:secret:<n>` | `secret` | el nombre |
| `arn:aws:s3:::<bucket>` o "Bucket <n>" | `s3_bucket` | el nombre del bucket |
| `i-…` | `ec2_instance` | el id |
| `sg-…`, `vpc-…`, `subnet-…`, `acl-…`, `vol-…`, `lt-…` | `security_group`, `vpc`, `subnet`, `nacl`, `ebs_volume`, `launch_template` | el id |
| `db-…` o identificador de RDS | `rds_instance` (o `rds_cluster`) | el `DBInstanceIdentifier` / ARN |
| `arn:aws:elasticloadbalancing:…` | `elbv2` | el ARN |
| `arn:aws:dynamodb:…:table/<n>` | `dynamodb_table` | el nombre |

`region`: la que diga la nota o el ARN. Tipos globales (`s3_bucket`, `iam_*`, `cloudfront_distribution`) van con `us-east-1`. Para otros tipos (EFS, ASG, WAF, ACM, EKS, API Gateway, CloudFront, ElastiCache, backup) consultar `references/inventory.json`.

## 6. Resolver un recurso por ID (modo `resource`)

El prefijo o el ARN determinan el tipo. Se audita el recurso y su contexto inmediato:

| Recurso | Contexto auditado |
|---|---|
| EC2 (`i-…`) | Security groups, volúmenes EBS, instance profile y su rol, subnet (ruta a IGW, IP pública), flow logs de la VPC |
| RDS | Subnet group, SGs, clave KMS, backups, parameter group (forzar SSL) |
| Bucket S3 | Políticas, Block Public Access, cifrado, versionado, logging |

Para el contexto, agregar al `resources` del alcance los SG, volúmenes y rol que salgan del propio recurso o de la nota del vault. Sin credenciales, solo se reporta lo que el vault diga de ese ID.

**Si el pedido es un ID sin vault ni credenciales:** parar. Decir en un mensaje corto que hace falta al menos una fuente y ofrecer las dos opciones: (a) la ruta de un vault con notas de ese recurso, o (b) un perfil AWS de solo lectura (`AWS_PROFILE`, idealmente con `SecurityAudit` + `ViewOnlyAccess`). No dar una lista especulativa de "qué se revisaría" ni un HTML de ejemplo.

## 7. Claims del vault: cuándo usar cada `kind`

Esquema completo en `references/report-format.md`.

| Situación | `kind` | Notas |
|---|---|---|
| El vault afirma algo distinto de lo real | `DRIFT` | Con `vault_claim` (lo que dice la nota), `actual` (lo que muestra la cuenta) y `vault_note` (ruta de la nota). Si aplica un chequeo, su `check_id`. |
| Hay un recurso vivo que el vault no menciona | `UNDOCUMENTED` | Severidad `low` por defecto. Con `resource` del inventario. |
| Sin credenciales: el vault dice que cumple | `DOCUMENTED_ONLY` | No es `PASS`. |
| Sin credenciales o `proposed`: el vault dice que falta o está pendiente | `DOCUMENTED_GAP` | Con el `check_id` del chequeo que cubriría ese control. |
| El vault recomienda algo que haría fallar tests (ahorros de costo) | `DRIFT` con `breaks_tests` | Mensaje: "esta recomendación del vault rompería <test>". Severidad mínima `high`. |
| Un `PENDING_CLAUDE` que Claude resolvió | `EVAL` | Una por fila pendiente. |

Reglas: un claim con `check_id` que no está en el catálogo genera una advertencia; si es una observación libre, `check_id: null` y la frase "observación de Claude, fuera del catálogo" en `actual`. Con credenciales la realidad manda: comparar con `inventory.json` y `checks-result.json`, no con lo que el vault dice de sí mismo.

## 8. Carpeta de evidencia extra

Se leen solo `.md`, `.html` y `.pdf` (los PDFs con Read por páginas). Nunca `.env*`, claves ni archivos sin extensión conocida. Lo que afirmen entra como claims con `vault_note` = ruta del archivo, y cuenta como afirmación del vault (no como verificación). Suele estar fuera del vault: tampoco se escribe ahí.

## 9. Secretos y archivos sensibles junto al vault

- Una nota `.md` con una clave o un `aws_secret_access_key`: el indexador la reporta (`secrets_detected`) y `assemble_findings.py` genera un `FAIL` `critical` solo. Claude no repite el valor en ningún lado.
- Un `.env*`, `credentials`, `*.pem` o `*.key` en la carpeta del vault o de evidencia: **no se abre ni con comandos que impriman parte del contenido, ni para "mostrar solo los nombres"**. Se detecta por nombre (`find "<carpeta>" -name '.env*' -o -name '*.pem' -o -name '*.key'`), se reporta como claim `UNDOCUMENTED` con `severity: "critical"` y `check_id: null` (ver paso 6 de `SKILL.md`) y se recomienda rotar y sacar el archivo. Nota: el reporte lo muestra como `UNDOCUMENTED` crítico, no como `FAIL`, porque el skill no verifica el contenido.
