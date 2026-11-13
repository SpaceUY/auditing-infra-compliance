# Remediación: reglas de los comandos de CloudShell

Se carga al revisar los arreglos (paso 9), al explicarle al usuario cómo aplicarlos y cuando alguien pide "arreglalo vos". **Los arreglos viven en el catálogo** (`references/checks/<dominio>.json`, campo `remediation`) y el ensamblador los instancia en `findings.json`. Claude no escribe, edita ni "mejora" comandos: los revisa, los explica y los marca.

## 1. Los comandos nunca se ejecutan

- Ni Claude ni los scripts ejecutan un comando de remediación. Se escriben en `findings.json` y en el HTML; los pega una persona en AWS CloudShell, después de leerlos.
- No ofrecer "aplicarlo si me das acceso", "preparar un PR", "generar el Terraform/CDK" ni pedir un perfil de escritura. La respuesta a "arreglalo vos" es: no ejecuto cambios; el reporte trae cada arreglo con botón Copy, el sello de verificación y el orden sugerido.
- Si falta un arreglo (hallazgo `FAIL` sin comandos, `gaps` de la verificación), se informa como faltante. No se inventa uno con `aws` ad hoc.

**Solo lo verificado lleva arreglo.** `FAIL`, `DOCUMENTED_GAP` y un `DRIFT` o un `UNDOCUMENTED` con `actual_status: FAIL` conservan pasos y comandos. En `DOCUMENTED_ONLY`, `PASS`, `N/A`, `NO_VERIFICADO` y los demás `DRIFT` y `UNDOCUMENTED` el ensamblador deja `steps: []` y `commands: []`, deja solo `verify_after` (el HTML lo presenta como "Verificar con") y agrega `note_status`: "no verificado: no aplicar sin confirmar". Por ejemplo, un `DOCUMENTED_ONLY` de cifrado de RDS no muestra la migración con downtime. Claude no reconstruye esos comandos ni los menciona como algo para aplicar. La verificación (paso 9) evalúa todo hallazgo con comandos, `DOCUMENTED_GAP` incluido, por eso los `__COMPLETAR_*__`, los sellos y el orden de aplicación los cubren.

## 2. Los cuatro `kind`

| `kind` | Qué es | Qué hace Claude |
|---|---|---|
| `cli` | Uno o pocos comandos que arreglan el problema sin decisiones del usuario. | Revisar dependencias en el vault; si riesgo `medium`/`high`, claim de verificación. |
| `cli_with_decision` | Hay un valor que decide el usuario (días de retención, email del owner, CIDR de la oficina, ARN de una clave). El comando trae `__COMPLETAR_<NOMBRE>__` y `notes` explica la decisión. | Pedir o recordar el dato; **no inventarlo** ni "completarlo" con un valor plausible. |
| `planned_change` | Multi-paso, destructivo o con downtime (cifrar una RDS existente, migrar una clave, reducir permisos IAM). Lleva `steps` numerados, advertencia en `notes`, `risk` y `downtime`. | Explicar que es un cambio planificado y no un one-liner; nunca presentarlo como "un comando". Revisar contra el vault qué depende del recurso. |
| `console_only` | No se puede por CLI (MFA del root, configuraciones de consola). `steps` en lenguaje llano, sin comandos. | Pasar los pasos tal cual; no escribir comandos "equivalentes". |

`remediation.risk` es `low` \| `medium` \| `high`; `downtime` es booleano; `verify_after` es el comando de solo lectura para comprobar el arreglo.

Reglas del catálogo (validadas por `validate_catalog.py`): cada arreglo que no es `console_only` tiene `verify_after`; cada `planned_change` tiene al menos 2 pasos y `notes` con la advertencia.

## 3. Placeholders, variables y valores a completar

- **Variables al inicio de cada bloque:** `REGION="…"` y `ACCOUNT_ID="…"`, y las que el bloque necesite (`SG_ID`, `DB_ID`, `TRAIL_NAME`…) entre comillas dobles. El resto del bloque las usa como `"$REGION"`.
- **Placeholders del catálogo**, resueltos por `assemble_findings.py` con sustitución plana: `{resource_id}`, `{region}`, `{account_id}`, `{resource_name}`, `{resource_arn}` y `{detail_json:<clave>}` (el JSON de `detail[<clave>]` entre comillas simples, para comandos con la regla exacta, por ejemplo `--ip-permissions` con solo las reglas ofensoras).
- **Valor desconocido o inseguro:** queda como `__COMPLETAR_<NOMBRE>__` (por ejemplo `__COMPLETAR_OWNER_EMAIL__`, `__COMPLETAR_KMS_KEY_ARN__`). También si el valor trae comillas, espacios, `$`, comillas invertidas o saltos de línea (no se inyecta en un comando). El HTML los resalta y cuenta; `verify_remediation.py` los marca `REVISAR` y los suma a `completar_pendientes`.
- **Un `{placeholder}` sin resolver** que llegue al HTML es un `CONFLICTO`: no se entrega; revisar el claim (`resource.id`, `region`) y volver a ensamblar.
- El formato es `__COMPLETAR_<NOMBRE>__` y **no** `<<COMPLETAR: …>>`: en bash `<<` abre un heredoc y deja colgada la sesión de CloudShell. Un `<<` en un comando es un `CONFLICTO` de higiene.

## 4. Higiene de los comandos

- **Sin `set -e`:** cerraría la sesión de CloudShell ante el primer error. Es `CONFLICTO` de higiene.
- **Encadenar con `&&`** toda línea destructiva o dependiente de la anterior (`create-db-snapshot … && aws rds wait … && …`). Los "create" idempotentes que pueden fallar porque ya existen van sueltos.
- **Nunca `--force`, `--delete`, `s3 rm`/`s3 rb`, ni `delete-*`, `terminate-*`, `deregister-*`, `detach-*`, `disable-*`, `stop-*`, `remove-*`, `revoke-*` ni comandos que reemplazan una política (`put-bucket-policy`, `put-key-policy`, `update-account-password-policy`) sin el aviso correspondiente:** el arreglo debe ser `planned_change`, o `cli_with_decision` con `notes` que expliquen el riesgo. Si no, el verificador lo marca `REVISAR` (`destructivo_sin_aviso`). Un comando que parece de una línea y destruye datos o acceso es un error de diseño; Claude no lo reescribe, lo marca en `verification-claims.json` y se lo advierte al usuario.
- **Revocar con la regla exacta**, no con filtros amplios: el catálogo arma el `revoke-security-group-ingress` con el JSON de las reglas ofensoras, no `--cidr 0.0.0.0/0` genérico.
- **No sobrescribir políticas compartidas** (SNS, SQS, bucket, key policy): el arreglo debe agregar el statement, no reemplazar el documento. Una key policy reemplazada puede dejar la clave inaccesible: conservar el statement de la raíz de la cuenta.
- **Cuidado con efectos laterales conocidos:** un `UPSERT` de TXT en el apex puede pisar otros valores TXT; forzar la rotación de DKIM cambia los tokens y CNAME; `--apply-immediately` aplica también otros cambios pendientes. Si el vault muestra que el recurso los usa, va como claim de verificación.

## 5. Qué revisa Claude en la etapa de verificación

Para cada hallazgo `FAIL` con `REVISAR`/`CONFLICTO` y para todo arreglo `medium` o `high` presente en `per_finding` de `verification.json` (los de solo verificación no lo están): qué depende del recurso según el vault y el inventario (una Lambda que usa la clave, un servicio que entra por el SSH que se cierra, un cliente HTTP que usa el bucket), y si el vault tiene una recomendación contraria. Resultado: `verification-claims.json` (esquema en `references/report-format.md`). Un `CONFLICTO` del script nunca se baja.

Reglas de conflicto iniciales (`references/conflict-rules.json`): cerrar el 80 de un SG de ALB con redirección (`CR-001`), CloudTrail con CMK sin permiso en la key policy (`CR-002`), revocar SSH/RDP sin SSM (`CR-003`), IMDSv2 con SDKs viejos (`CR-004`), rotar o desactivar access keys en uso (`CR-005`), `Deny` sin TLS en S3 (`CR-006`), cifrar un recurso existente con migración y downtime (`CR-007`), quitar `VantaNonProd` a un recurso de producción (`CR-008`), `put-key-policy` (`CR-009`), Multi-AZ con costo y failover breve (`CR-010`).

## 6. Cómo se lo explicás al usuario

- Aplicar **en el orden sugerido** (`apply_order`): identidad, logging y detección (visibilidad antes de tocar nada), claves KMS, cifrado, red, datos y backups, monitoreo, tags e integración; `planned_change` al final de cada grupo.
- Completar todos los `__COMPLETAR_*__` antes de pegar; no pegar bloques con `CONFLICTO` sin resolver el motivo.
- El botón "Copiar arreglos de bajo riesgo" agrupa solo `cli` de riesgo bajo, sin valores pendientes y excluye los `REVISAR` y los `CONFLICTO`; igual se leen antes de pegar. "Copiar todo" (los bloques de una tarjeta de una vez) existe solo para arreglos `cli`: un `cli_with_decision` o un `planned_change` se copia y se aplica bloque por bloque, leyendo cada uno.
- Un arreglo que declara `downtime: true` nunca sale `OK`: el piso es `REVISAR` ("el arreglo declara downtime"), así que tampoco entra al copiado de bajo riesgo.
- Si se vuelve a correr `assemble_findings.py` después de verificar, el reporte muestra "verificación desactualizada": repetir `verify_remediation.py` y volver a renderizar.
- Después de aplicar, correr el comando "verificar después" de cada tarjeta, o volver a correr la auditoría.
- Recursos de "No tocar sin revisar": cambiarlos puede poner en rojo tests que hoy pasan; la tarjeta lista cuáles.
- Si el vault recomienda ahorros que rompen tests (apagar Multi-AZ, borrar Flow Logs, borrar el bucket destino de access logs de CloudTrail), el reporte lo marca `DRIFT` `high` con "esta recomendación del vault rompería <test>": se lo decís al usuario, no se aplica.
