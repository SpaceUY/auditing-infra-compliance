# infra-compliance-audit

Skill de Claude Code `auditing-infra-compliance`: pre-audita infraestructura AWS contra SOC 2 y ISO 27001:2022 y
entrega un HTML autocontenido con hallazgos, mapeos a los tests de Drata y Vanta y comandos de CloudShell
listos para copiar.

El diseño está en `docs/specs/2026-11-12-infra-compliance-audit-design.md` y el plan de implementación en
`docs/plans/2026-11-12-infra-compliance-audit.md`.

## Qué hace

- Lee un vault de Obsidian (tipado o libre) para saber qué debería existir y para qué sirve.
- Verifica la cuenta AWS con credenciales de **solo lectura**: inventario más el catálogo de chequeos (ver `validate_catalog.py --list`) en los
  dominios de IAM, logging, detección, cifrado, red, cómputo, datos, monitoreo, inventario, integración y email.
- Compara lo documentado con lo desplegado y lo informa como `DRIFT`, `UNDOCUMENTED`, `DOCUMENTED_ONLY` o
  `DOCUMENTED_GAP`.
- Produce `report.html`, `findings.json`, `checks-result.json`, `inventory.json` y `raw/` en
  `./compliance-reports/<plataforma>-<alcance>-<fecha>/`, siempre fuera del vault.
- Verifica los comandos de remediación sin ejecutarlos (sintaxis, placeholders pendientes, conflictos entre
  arreglos, tests que dependen del recurso) y sugiere un orden de aplicación.
- Los scripts deciden PASS/FAIL, arman los comandos, los mapeos y el HTML; Claude lee el vault, resuelve el
  alcance y juzga solo lo que los scripts no pueden decidir.

## Qué no hace

- No es una opinión de auditoría ni un puntaje: no hay porcentaje ni nota de cumplimiento, solo conteos por
  estado y severidad.
- No ejecuta ninguna operación de escritura en AWS. `aws_runner.py` admite solo `describe-*`, `list-*` y `get-*`
  (más `lookup-events` y `generate-credential-report`) y rechaza una denylist de lecturas que exponen secretos.
- No aplica arreglos: los comandos los pega una persona en CloudShell.
- No lee archivos `.env*`, `~/.aws/credentials`, `*.pem` ni `*.key`; los detecta solo por nombre.
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

No usar una identidad con `AdministratorAccess`: el skill lo advierte, pero no hace falta para auditar. Nunca
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

Hace falta al menos una fuente: un vault, credenciales de AWS, o ambos. Sin credenciales el skill trabaja solo
con el vault y todo lo que depende de AWS queda `DOCUMENTED_*` o `NO_VERIFICADO`.

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
