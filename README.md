# infra-compliance-audit

Skill de Claude Code `auditing-infra-compliance`: pre-audita infraestructura AWS contra SOC 2 y ISO 27001:2022 y
entrega un HTML autocontenido que dice si la infraestructura es óptima, con hallazgos, mapeos a los tests de Drata
y Vanta y comandos de CloudShell para que una persona los copie y los pegue.

**Regla absoluta: el skill solo informa.** Produce un reporte y comandos de remediación para un humano; **nunca
escribe en AWS ni aplica un arreglo** (ni Claude ni los scripts), aunque se lo pidan, "solo para probar", con otra
herramienta o con un perfil de escritura. No ofrece acceso, PRs ni IaC para aplicarlo.

El diseño está en `docs/specs/2026-11-12-infra-compliance-audit-design.md` y el plan de implementación en
`docs/plans/2026-11-12-infra-compliance-audit.md`.

## Qué hace

- Lee un vault de Obsidian (tipado o libre) para saber qué debería existir y para qué sirve.
- Verifica la cuenta AWS con credenciales de **solo lectura**: inventario más el catálogo de chequeos (ver `validate_catalog.py --list`) en los
  dominios de IAM, logging, detección, cifrado, red, cómputo, datos, monitoreo, inventario, integración y email.
- Muestra el progreso de la recolección por stderr (`--quiet` lo apaga) y escribe `checks-result.json` de forma
  incremental: una corrida interrumpida (exit `130`) deja un resultado parcial (`partial`, `pending_checks`) que el
  reporte declara como tal; las regiones bloqueadas por una SCP se informan como no verificadas.
- Compara lo documentado con lo desplegado y lo informa como `DRIFT`, `UNDOCUMENTED`, `DOCUMENTED_ONLY` o
  `DOCUMENTED_GAP`.
- Calcula un **veredicto** con la fuente que le den (credenciales AWS de solo lectura, el vault o ambos) y dice en qué
  se basa: `summary.verdict`, `summary.verdict_basis` (`aws`, `vault` o `aws+vault`) y la frase `summary.verdict_text`,
  lo primero que muestra el HTML. Con credenciales: `NO_OPTIMO` (algún `FAIL`, un `DRIFT`/`UNDOCUMENTED` cuyo estado
  real falla o una brecha documentada crítica o alta), `NO_VERIFICABLE` (corrida parcial, regiones bloqueadas,
  inventario incompleto o algo sin verificar) u `OPTIMO` (corrida completa, nada sin verificar y al menos un `PASS` o
  `FAIL` evaluado). Solo con el vault: `NO_OPTIMO` (brecha crítica/alta, secreto o claim que falla), `OPTIMO` (al menos
  un control documentado, ninguna brecha y nada del alcance sin documentar; sigue siendo "no verificado contra AWS")
  o `NO_VERIFICABLE` (con lo que el vault no documenta). No hay porcentaje ni nota.
- Sin ninguna fuente (ni vault ni credenciales) no hay reporte: `assemble_findings.py` termina con exit `2`
  ("sin fuentes"). Un `scope.json` que no selecciona nada (modo o dominio desconocido, recursos sin chequeos) o con
  `scope.regions` inválido hace terminar `collect.py` con exit `2` y un mensaje, sin escribir archivos. Si no se pueden
  listar las regiones (`ec2:DescribeRegions`) en modo `auto`, los chequeos de cuenta con llamadas regionales quedan
  `NO_VERIFICADO`, nunca `PASS` por mirar solo `us-east-1`.
- Produce `report.html`, `findings.json`, `checks-result.json`, `inventory.json` y `raw/` en
  `./compliance-reports/<plataforma>-<alcance>-<fecha>/`, siempre fuera del vault.
- Verifica los comandos de remediación sin ejecutarlos (sintaxis, placeholders pendientes, conflictos entre
  arreglos, tests que dependen del recurso) y sugiere un orden de aplicación.
- Los scripts deciden PASS/FAIL, arman los comandos, los mapeos y el HTML; Claude lee el vault, resuelve el
  alcance y juzga solo lo que los scripts no pueden decidir.

## Qué no hace

- No es una opinión de auditoría ni un puntaje: no hay porcentaje ni nota de cumplimiento, solo conteos por
  estado y severidad.
- **No escribe en AWS, jamás.** `aws_runner.py` admite solo `describe-*`, `list-*` y `get-*`
  (más `lookup-events`, `generate-credential-report` y la excepción acotada `inspector2 batch-get-account-status`),
  rechaza una denylist de lecturas que exponen secretos y las operaciones de nombre sensible (credential, password,
  token, secret…) salvo excepciones revisadas, y rechaza todo argumento `https://` o `http://` (la CLI intentaría
  descargarlo). Además solo corre los pares (servicio, operación) de `catalog.REVIEWED_OPERATIONS`: agregar una
  llamada exige agregarla ahí y `validate_catalog.py` falla si falta.
- **No aplica arreglos, ni siquiera si se lo piden o "para probar":** los comandos los pega una persona en
  CloudShell. Tampoco ofrece acceso de escritura, PRs ni IaC. Los arreglos que reemplazan una política o configuración
  leen primero la actual y se detienen (`DETENIDO`) si no pueden leerla; ninguno se ejecuta desde el skill.
- No lee archivos `.env*`, `~/.aws/credentials`, `*.pem` ni `*.key`; los detecta solo por nombre. La detección de
  secretos dentro de las notas tiene límites conocidos (nombres de secretos con forma de clave, "password valor" sin
  separador, tablas por columnas): una persona debe revisar esas notas (`references/vault-reading.md`).
- No escribe en el vault.
- No inventa nombres de tests de Drata o Vanta ni IDs de SOC 2 o ISO: usa solo lo que sale del catálogo y de
  `references/mappings/`. Un mapeo sin fuente se muestra como "inferido".
- No cubre Windows (Linux y macOS) ni consulta a Drata o Vanta en vivo (ver "Fase 2").

## Instalación

Requisitos: Python 3.10 o superior (solo biblioteca estándar), AWS CLI v2 y, de forma opcional, `dig` o
`nslookup` para los chequeos de DNS.

Desde la raíz del repo, enlazar el skill en la carpeta de skills de Claude Code:

```bash
ln -s "$PWD/auditing-infra-compliance" ~/.claude/skills/auditing-infra-compliance
```

## Permisos recomendados para el perfil de AWS

Usar un rol o usuario dedicado, de solo lectura, con las políticas administradas `SecurityAudit` y
`ViewOnlyAccess`. Si faltan, agregar además una política con estos permisos:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "backup:ListBackupJobs",
        "backup:ListRecoveryPointsByResource",
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

No usar una identidad con `AdministratorAccess`: el skill lo advierte, pero no hace falta para auditar (recomendado:
`SecurityAudit` + `ViewOnlyAccess`). Si alguien ofrece un perfil admin, Claude solo lo puede usar para la recolección de
solo lectura que permiten los scripts y nunca para aplicar un arreglo. Nunca
pegar claves en el chat; indicar solo el nombre del perfil (`AWS_PROFILE` o `--profile`). Si falta un permiso,
el chequeo correspondiente queda `NO_VERIFICADO` e indica cuál es.

## Cómo pedirlo

El skill se activa solo cuando el pedido encaja; el alcance se deduce de lo que se pide.

- **Modo `full`** (toda la cuenta):
  "Auditá la infraestructura de Acme Notes para SOC 2. El vault está en `~/vaults/acme-notes` y uso el perfil
  `acme-audit`."
- **Modo `feature`** (un flujo): "Revisá el envío de email de Acme Notes contra SOC 2." El skill resuelve los
  componentes desde el vault, te los muestra y espera tu confirmación antes de recolectar.
- **Modo `resource`** (un recurso por ID o ARN): "¿El bucket `acme-notes-uploads` pasa los tests de Drata?" o
  "Revisá `sg-0a1b2c3d4e5f60718` contra compliance."

Hace falta al menos una fuente: un vault, credenciales de AWS, o ambos. Con una sola de las dos fuentes el skill evalúa lo que le dan y
dice en qué se basa el veredicto. Sin credenciales trabaja solo con el vault: los hallazgos quedan `DOCUMENTED_*` (nada se
marca `PASS` ni `FAIL`) y el veredicto dice que no se verificó contra AWS.

## Pruebas

```bash
python3 -m unittest discover -s tests -v
python3 auditing-infra-compliance/scripts/validate_catalog.py
```

- Las pruebas usan solo la biblioteca estándar y un AWS falso (`tests/helpers.py`, `FakeRunner`): no llaman a
  AWS ni a la red y escriben solo en directorios temporales.
- `tests/test_e2e.py` recorre el pipeline completo con una cuenta ficticia de "Acme Notes": recolección,
  `findings.json`, HTML, verificación de arreglos y HTML con verificación; también el caso sin AWS.
- Los fixtures usan la plataforma ficticia "Acme Notes", la cuenta `111122223333`, la región `us-east-1` y el
  dominio `acme-notes.example`.
- `tests/skill-scenarios.md` describe los escenarios de comportamiento del skill (se prueban con subagentes).
- `docs/live-test-checklist.md` es la prueba en vivo, manual, con una cuenta real.

## Fase 2 (pendiente)

Solo aplica cuando hay conexiones disponibles; sin ellas no aparece en el reporte.

- **Drata MCP:** traer los tests que fallan y cruzarlos con los hallazgos ("coincide", "solo Drata", "solo el
  skill"). Solo lecturas.
- **Vanta:** el mismo cruce, por su API o su MCP si existe.
- **Prowler:** si está instalado y el usuario acepta, ingestar su salida como segunda opinión.
