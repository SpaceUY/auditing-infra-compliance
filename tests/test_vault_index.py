import builtins
import contextlib
import io
import json
import shutil
import tempfile
import time
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

import helpers
from helpers import FIXTURES_DIR

import vault_index

TYPED = FIXTURES_DIR / "typed-vault"
FREE = FIXTURES_DIR / "free-vault"


def titles(components):
    return {c["title"] for c in components}


class VaultCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def copy_vault(self, source):
        target = self.tmp / source.name
        shutil.copytree(source, target)
        return target

    @staticmethod
    def note(index, title):
        return next(n for n in index["notes"] if n["title"] == title)


class IndexTests(VaultCase):
    def test_detects_typed(self):
        self.assertEqual(vault_index.build_index(TYPED)["kind"], "typed")

    def test_detects_free(self):
        self.assertEqual(vault_index.build_index(FREE)["kind"], "free")

    def test_typed_by_frontmatter_ratio_without_meta(self):
        vault = self.tmp / "ratio"
        vault.mkdir()
        (vault / "a.md").write_text("---\ntype: system\n---\n# A\n", encoding="utf-8")
        (vault / "b.md").write_text("# B\n", encoding="utf-8")
        self.assertEqual(vault_index.build_index(vault)["kind"], "typed")
        (vault / "c.md").write_text("# C\n", encoding="utf-8")
        self.assertEqual(vault_index.build_index(vault)["kind"], "free")

    def test_parses_frontmatter_and_edges(self):
        index = vault_index.build_index(TYPED)
        lam = self.note(index, "Mailer Lambda")
        self.assertEqual((lam["type"], lam["status"]), ("system", "shipped"))
        self.assertEqual(lam["source"], ["acme-notes/services/mailer/handler.py"])
        self.assertEqual(lam["edges"], [{"relation": "depends on", "target": "Mailer Role", "layer": "structural"}])
        email = self.note(index, "Email delivery")
        self.assertEqual([(e["relation"], e["target"]) for e in email["edges"]],
                         [("depends on", "SES Identity"), ("depends on", "Mailer Lambda"),
                          ("depends on", "Mail Queue"), ("depends on", "DMARC reject policy"),
                          ("requires", "PII handling")])
        self.assertEqual(self.note(index, "DMARC reject policy")["status"], "proposed")
        self.assertIn("Mailer Role", lam["links"])
        self.assertEqual(lam["path"], "systems/Mailer Lambda.md")

    def test_meta_notes_are_not_indexed_as_notes(self):
        paths = {n["path"] for n in vault_index.build_index(TYPED)["notes"]}
        self.assertFalse(any(p.startswith("_meta/") for p in paths))

    def test_associative_layer_from_section(self):
        vault = self.tmp / "v"
        vault.mkdir()
        (vault / "a.md").write_text(
            "---\ntype: concept\n---\n# A\n\n## Structural\n- requires → [[B]]\n\n## Associative\n"
            "- resembles → [[B]] because shape\n", encoding="utf-8")
        (vault / "b.md").write_text("---\ntype: concept\n---\n# B\n", encoding="utf-8")
        edges = self.note(vault_index.build_index(vault), "a")["edges"]
        self.assertEqual([(e["relation"], e["layer"]) for e in edges],
                         [("requires", "structural"), ("resembles", "associative")])

    def test_extracts_aws_ids(self):
        index = vault_index.build_index(TYPED)
        ids = self.note(index, "Mailer Lambda")["aws_ids"]
        self.assertIn({"kind": "arn", "value": "arn:aws:lambda:us-east-1:111122223333:function:acme-notes-mailer"}, ids)
        self.assertIn({"kind": "sg", "value": "sg-0123456789abcdef0"}, ids)
        self.assertIn({"kind": "vpc", "value": "vpc-0a1b2c3d4e5f60718"}, ids)
        free = vault_index.build_index(FREE)
        self.assertIn({"kind": "db", "value": "db-ACMENOTES0123456789ABCDEFG"},
                      self.note(free, "RDS - acme-db")["aws_ids"])
        self.assertIn({"kind": "subnet", "value": "subnet-0a1b2c3d"}, self.note(free, "VPC")["aws_ids"])

    def test_masks_keys_in_index(self):
        vault = self.copy_vault(FREE)
        secret_path = helpers.make_secret_note(vault)
        key = "AKIA" + "TESTKEYABCDEMNOP"
        (vault / "Credenciales 2.md").write_text(
            "# Otro\n\n| Campo | Valor |\n|---|---|\n| aws_secret_access_key | wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY |\n"
            "| Contacto | admin@acme-notes.example |\n", encoding="utf-8")
        index = vault_index.build_index(vault)
        dumped = json.dumps(index, ensure_ascii=False)
        self.assertNotIn(key, dumped)
        self.assertNotIn("wJalrXUtnFEMI", dumped)
        self.assertNotIn("admin@acme", dumped)
        self.assertIn("a***@acme-notes.example", dumped)
        self.assertIn({"path": secret_path.name, "pattern": "aws_access_key_id"}, index["secrets_detected"])
        self.assertIn({"path": "Credenciales 2.md", "pattern": "aws_secret_access_key"}, index["secrets_detected"])
        self.assertFalse([i for n in index["notes"] for i in n["aws_ids"] if i["value"].startswith("AKIA")])

    def test_ignores_dotfiles_and_env(self):
        vault = self.copy_vault(FREE)
        (vault / ".env").write_text("DB_PASSWORD=hunter2\n", encoding="utf-8")
        (vault / ".hidden.md").write_text("# Oculta\nhunter2\n", encoding="utf-8")
        (vault / "server.pem").write_text("hunter2\n", encoding="utf-8")
        (vault / "api.key").write_text("hunter2\n", encoding="utf-8")
        (vault / ".git").mkdir()
        (vault / ".git" / "note.md").write_text("# Git\nhunter2\n", encoding="utf-8")
        (vault / ".obsidian" / "plugins" / "dataview").mkdir(parents=True)
        (vault / ".obsidian" / "plugins" / "dataview" / "main.md").write_text("hunter2\n", encoding="utf-8")
        real_open = builtins.open

        def guarded(file, *args, **kwargs):
            name = Path(str(file)).name
            if name.startswith(".") or name.endswith((".pem", ".key")) or ".git" in Path(str(file)).parts \
                    or ".obsidian" in Path(str(file)).parts:
                raise AssertionError(f"forbidden read: {file}")
            return real_open(file, *args, **kwargs)

        with mock.patch.object(builtins, "open", guarded):
            index = vault_index.build_index(vault)
        self.assertNotIn("hunter2", json.dumps(index))
        self.assertEqual(index["obsidian_plugins"], ["dataview"])
        self.assertEqual(len(index["notes"]), 6)

    def test_symlinks_are_not_followed(self):
        vault = self.copy_vault(FREE)
        outside = self.tmp / "outside.md"
        outside.write_text("# Fuera\n", encoding="utf-8")
        (vault / "link.md").symlink_to(outside)
        paths = {n["path"] for n in vault_index.build_index(vault)["notes"]}
        self.assertNotIn("link.md", paths)

    def test_broken_links_reported(self):
        index = vault_index.build_index(FREE)
        self.assertEqual(index["broken_links"],
                         [{"from": "Runbook de guardia.md", "target": "Checklist de rotación de claves"}])
        self.assertEqual(vault_index.build_index(TYPED)["broken_links"], [])

    def test_free_vault_inferred_types_and_kv(self):
        index = vault_index.build_index(FREE)
        self.assertEqual(self.note(index, "RDS - acme-db")["inferred_type"], "rds_instance")
        self.assertEqual(self.note(index, "S3 - uploads")["inferred_type"], "s3_bucket")
        self.assertEqual(self.note(index, "VPC")["inferred_type"], "vpc")
        self.assertEqual(self.note(index, "ALB - acme-public")["inferred_type"], "elbv2")
        self.assertIsNone(self.note(index, "Acme Notes")["inferred_type"])
        rds = self.note(index, "RDS - acme-db")
        self.assertEqual(rds["kv"]["KMS"], "CMK propia")
        self.assertEqual(rds["kv"]["Motor"], "PostgreSQL 15")
        self.assertNotIn("Campo", rds["kv"])
        self.assertIsNone(rds["type"])
        self.assertIn("## Conectado a", rds["headings"])
        self.assertTrue(all(n["inferred_type"] is None for n in vault_index.build_index(TYPED)["notes"]))

    def write_vault(self, **notes):
        vault = self.tmp / "custom"
        vault.mkdir(exist_ok=True)
        for name, text in notes.items():
            (vault / f"{name}.md").write_text(text, encoding="utf-8")
        return vault

    def test_arn_glued_to_key_and_minified_json_do_not_leak(self):
        key = "AKIA" + "TESTKEYABCDEMNOP"
        secret = "wJalrXUtnFEM" + "IK7MDENGbPxRfiCYEXAMPLEKEY"
        arn = "arn:aws:iam::111122223333:user/ci"
        vault = self.write_vault(
            blob=f'# Blob\n\n{{"Arn":"{arn}","AccessKeyId":"{key}","SecretAccessKey":"{secret}"}}\n',
            glued=f"# Glued\n\n{arn}{key} y {arn},{key}\n",
            meta=f"---\ntype: {key}\nstatus: {key}\n---\n# Meta\n")
        index = vault_index.build_index(vault)
        dumped = json.dumps(index, ensure_ascii=False)
        self.assertNotIn(key, dumped)
        self.assertNotIn(secret, dumped)
        self.assertIn({"kind": "arn", "value": arn}, self.note(index, "blob")["aws_ids"])
        self.assertIn({"kind": "arn", "value": arn}, self.note(index, "glued")["aws_ids"])
        self.assertEqual(self.note(index, "meta")["type"], "AKIA…MNOP")
        self.assertEqual(self.note(index, "meta")["status"], "AKIA…MNOP")

    def test_emails_inside_identifiers_are_not_masked(self):
        arn = "arn:aws:ses:us-east-1:111122223333:identity/noreply@acme-notes.example"
        index = vault_index.build_index(self.write_vault(ses=f"# SES\n\n{arn}\n"))
        self.assertEqual(self.note(index, "ses")["aws_ids"], [{"kind": "arn", "value": arn}])

    def test_secret_assignment_variants_are_detected_and_masked(self):
        secret = "wJalrXUtnFEM" + "IK7MDENGbPxRfiCYEXAMPLEKEY"
        lines = {
            "bold": f"**aws_secret_access_key**: {secret}",
            "tick": f"`aws_secret_access_key` = {secret}",
            "prefix": f"prod_secret_access_key={secret}",
            "suffix": f"AWS_SECRET_ACCESS_KEY_PROD={secret}",
            "human": f"| Secret Access Key | {secret} |",
            "camel": f'{{"SecretAccessKey": "{secret}"}}',
        }
        vault = self.write_vault(**{name: f"# {name}\n\n{line}\n" for name, line in lines.items()},
                                 session=f"# s\n\naws_session_token = {secret}\n")
        index = vault_index.build_index(vault)
        dumped = json.dumps(index, ensure_ascii=False)
        self.assertNotIn(secret, dumped)
        for name in lines:
            self.assertIn({"path": f"{name}.md", "pattern": "aws_secret_access_key"}, index["secrets_detected"], name)
        self.assertIn({"path": "session.md", "pattern": "aws_session_token"}, index["secrets_detected"])
        self.assertEqual(self.note(index, "human")["kv"], {"Secret Access Key": "[REDACTED]"})

    def test_access_key_glued_to_text_is_detected_and_masked(self):
        key = "AKIA" + "TESTKEYABCDEMNOP"
        variants = {"before": f"x{key}", "after": f"{key}x", "digit": f"{key}1"}
        vault = self.write_vault(**{n: f"# {n}\n\n{v}\n" for n, v in variants.items()})
        index = vault_index.build_index(vault)
        self.assertNotIn(key, json.dumps(index))
        for name in variants:
            self.assertIn({"path": f"{name}.md", "pattern": "aws_access_key_id"}, index["secrets_detected"], name)

    def test_bom_is_stripped_from_frontmatter(self):
        vault = self.tmp / "bom"
        vault.mkdir()
        (vault / "a.md").write_bytes(b"\xef\xbb\xbf---\ntype: system\n---\n# A\n")
        self.assertEqual(vault_index.build_index(vault)["notes"][0]["type"], "system")

    def test_missing_vault_raises(self):
        with self.assertRaises(ValueError):
            vault_index.build_index(self.tmp / "nope")
        (self.tmp / "file.md").write_text("# x\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            vault_index.build_index(self.tmp / "file.md")

    def test_meta_edges_alone_marks_typed(self):
        vault = self.tmp / "edges-only"
        (vault / "_meta").mkdir(parents=True)
        (vault / "_meta" / "edges.md").write_text("# Edge index\n", encoding="utf-8")
        (vault / "a.md").write_text("# A\n", encoding="utf-8")
        self.assertEqual(vault_index.build_index(vault)["kind"], "typed")

    def test_breadcrumbs_are_parents_not_links(self):
        index = vault_index.build_index(FREE)
        s3 = self.note(index, "S3 - uploads")
        self.assertEqual((s3["links"], s3["parents"]), ([], ["Acme Notes"]))
        self.assertEqual(vault_index.build_index(FREE)["broken_links"],
                         [{"from": "Runbook de guardia.md", "target": "Checklist de rotación de claves"}])

    def test_cli_form_is_detected_in_the_index(self):
        secret = "wJalrXUtnFEM" + "IK7MDENGbPxRfiCYEXAMPLEKEY"
        vault = self.tmp / "cli"
        vault.mkdir()
        (vault / "n.md").write_text(f"# N\n\naws iam create --secret-access-key {secret}\n", encoding="utf-8")
        index = vault_index.build_index(vault)
        self.assertNotIn(secret, json.dumps(index))
        self.assertEqual(index["secrets_detected"], [{"path": "n.md", "pattern": "aws_secret_access_key"}])

    def test_inferred_types_exist_in_inventory(self):
        specs = json.loads((helpers.SKILL_DIR / "references" / "inventory.json").read_text(encoding="utf-8"))
        self.assertLessEqual(set(vault_index.INFERRED_TYPES.values()), set(specs))


class FeatureTests(VaultCase):
    def test_feature_typed_email_components(self):
        index = vault_index.build_index(TYPED)
        result = vault_index.resolve_feature(index, "email delivery")
        self.assertEqual(result["chosen"], "systems/Email delivery.md")
        self.assertEqual(result["confidence"], "typed")
        self.assertEqual(titles(result["components"]),
                         {"SES Identity", "Mailer Lambda", "Mail Queue", "Mailer Role", "DMARC reject policy"})
        role = next(c for c in result["components"] if c["title"] == "Mailer Role")
        self.assertEqual((role["depth"], role["via"]), (2, ["depends on"]))
        self.assertTrue(any(i["value"].startswith("arn:aws:iam") for i in role["aws_ids"]))
        proposed = next(c for c in result["components"] if c["title"] == "DMARC reject policy")
        self.assertEqual(proposed["status"], "proposed")
        self.assertEqual(result["constraints"], ["constraints/PII handling.md"])
        self.assertTrue(result["pii"])

    def test_feature_typed_depth_limit(self):
        index = vault_index.build_index(TYPED)
        result = vault_index.resolve_feature(index, "Email delivery", max_depth=1)
        self.assertNotIn("Mailer Role", titles(result["components"]))

    def test_feature_typed_only_systems_are_components(self):
        index = vault_index.build_index(TYPED)
        result = vault_index.resolve_feature(index, "Email delivery")
        self.assertFalse([c for c in result["components"] if not c["path"].startswith("systems/")])

    def test_feature_typed_inbound_is_part_of(self):
        index = vault_index.build_index(TYPED)
        self.note(index, "Mail Queue")["edges"].append(
            {"relation": "is part of", "target": "Email delivery", "layer": "structural"})
        extra = {"path": "systems/Delivery Log Group.md", "title": "Delivery Log Group", "type": "system",
                 "status": "shipped", "source": [], "links": [], "aws_ids": [], "kv": {}, "headings": [],
                 "inferred_type": None,
                 "edges": [{"relation": "is part of", "target": "Email delivery", "layer": "structural"}]}
        index["notes"].append(extra)
        result = vault_index.resolve_feature(index, "Email delivery")
        log = next(c for c in result["components"] if c["title"] == "Delivery Log Group")
        self.assertEqual((log["via"], log["depth"]), (["is part of"], 1))

    def test_feature_typed_ignores_superseded(self):
        index = vault_index.build_index(TYPED)
        self.note(index, "Mail Queue")["status"] = "superseded"
        result = vault_index.resolve_feature(index, "Email delivery")
        self.assertNotIn("Mail Queue", titles(result["components"]))

    def test_feature_ambiguous_returns_candidates(self):
        index = vault_index.build_index(TYPED)
        result = vault_index.resolve_feature(index, "mailer")  # no exact title, no H1 equal; two H1 contain it
        self.assertIsNone(result["chosen"])
        self.assertEqual(sorted(result["candidates"]), ["systems/Mailer Lambda.md", "systems/Mailer Role.md"])
        self.assertEqual(result["components"], [])

    def test_feature_match_ignores_case_and_accents(self):
        index = vault_index.build_index(FREE)
        result = vault_index.resolve_feature(index, "RUNBOOK DE GUARDÍA")
        self.assertEqual(result["chosen"], "Runbook de guardia.md")

    def test_feature_body_match(self):
        index = vault_index.build_index(TYPED)
        result = vault_index.resolve_feature(index, "easy dkim")
        self.assertEqual(result["candidates"], ["systems/SES Identity.md"])
        self.assertEqual(result["chosen"], "systems/SES Identity.md")

    def test_feature_not_found_empty(self):
        index = vault_index.build_index(TYPED)
        result = vault_index.resolve_feature(index, "Blockchain ledger")
        self.assertEqual(result, {"candidates": [], "chosen": None, "components": [], "constraints": [],
                                  "pii": False, "confidence": "typed"})

    def test_feature_free_wikilinks_depth_two(self):
        index = vault_index.build_index(FREE)
        result = vault_index.resolve_feature(index, "Acme Notes")
        self.assertEqual(result["confidence"], "inferred")
        self.assertEqual(titles(result["components"]), {"RDS - acme-db", "S3 - uploads", "VPC", "ALB - acme-public"})
        self.assertEqual({c["title"]: c["depth"] for c in result["components"]}["VPC"], 1)
        self.assertEqual(result["constraints"], [])
        self.assertTrue(result["pii"])  # S3 note mentions datos personales

    def test_feature_free_filters_non_aws_notes(self):
        index = vault_index.build_index(FREE)
        result = vault_index.resolve_feature(index, "Runbook de guardia")
        self.assertEqual(result["components"], [])
        self.assertFalse(result["pii"])

    def test_pii_false_without_keywords(self):
        index = vault_index.build_index(FREE)
        self.assertFalse(vault_index.resolve_feature(index, "VPC")["pii"])


    def test_feature_free_does_not_follow_breadcrumbs(self):
        index = vault_index.build_index(FREE)
        result = vault_index.resolve_feature(index, "S3 - uploads")
        self.assertEqual(result["chosen"], "S3 - uploads.md")
        self.assertEqual(result["components"], [])

    def test_feature_matches_partial_title_without_h1(self):
        vault = self.tmp / "noh1"
        vault.mkdir()
        (vault / "Pasarela de pagos.md").write_text("Texto sin encabezado.\n", encoding="utf-8")
        index = vault_index.build_index(vault)
        result = vault_index.resolve_feature(index, "pasarela")
        self.assertEqual(result["chosen"], "Pasarela de pagos.md")

    def test_feature_typed_normalizes_qualified_links(self):
        vault = self.tmp / "q"
        (vault / "systems").mkdir(parents=True)
        (vault / "systems" / "F.md").write_text(
            "---\ntype: system\n---\n# F\n\n## Structural\n- depends on → [[systems/G]]\n"
            "- depends on → [[H|alias]]\n- requires → [[I#sec]]\n- enables → [[J.md]]\n", encoding="utf-8")
        for name in "GHIJ":
            (vault / "systems" / f"{name}.md").write_text(f"---\ntype: system\n---\n# {name}\n", encoding="utf-8")
        index = vault_index.build_index(vault)
        self.assertEqual(index["broken_links"], [])
        result = vault_index.resolve_feature(index, "F")
        self.assertEqual(titles(result["components"]), {"G", "H", "I", "J"})

    def test_feature_typed_matches_nfd_links_and_extra_spaces(self):
        vault = self.tmp / "nfd"
        (vault / "systems").mkdir(parents=True)
        nfc = unicodedata.normalize("NFC", "Facturación")
        nfd = unicodedata.normalize("NFD", "Facturación")
        (vault / "systems" / "F.md").write_text(
            f"---\ntype: system\n---\n# F\n\n## Structural\n- depends on → [[{nfd}]]\n"
            "- depends on → [[Mail   Queue]]\n", encoding="utf-8")
        for name in (nfc, "Mail Queue"):
            (vault / "systems" / f"{name}.md").write_text(f"---\ntype: system\n---\n# {name}\n", encoding="utf-8")
        index = vault_index.build_index(vault)
        self.assertEqual(index["broken_links"], [])
        result = vault_index.resolve_feature(index, "F")
        self.assertEqual(titles(result["components"]), {nfc, "Mail Queue"})

    def test_body_ignores_symlinks_dirs_and_dot_paths(self):
        vault = self.tmp / "b"
        vault.mkdir()
        (vault / "a.md").write_text("# A\n\ncontenido\n", encoding="utf-8")
        index = vault_index.build_index(vault)
        outside = self.tmp / "outside.md"
        outside.write_text("zzzunico\n", encoding="utf-8")
        (vault / "a.md").unlink()
        (vault / "a.md").symlink_to(outside)
        (vault / ".git").mkdir()
        (vault / ".git" / "n.md").write_text("zzzunico\n", encoding="utf-8")
        (vault / "dir.md").mkdir()
        base = {"title": "x", "type": None, "status": None, "source": [], "edges": [], "links": [],
                "aws_ids": [], "kv": {}, "headings": [], "inferred_type": None}
        index["notes"] += [{**base, "path": ".git/n.md"}, {**base, "path": "dir.md"}]
        self.assertEqual(vault_index.resolve_feature(index, "zzzunico")["candidates"], [])


class CliTests(VaultCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = vault_index.main(list(argv))
        return code, out.getvalue()

    def test_index_then_feature(self):
        target = self.tmp / "vault-index.json"
        code, _ = self.run_cli("index", str(TYPED), "-o", str(target))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["kind"], "typed")
        code, text = self.run_cli("feature", str(target), "Email delivery")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["chosen"], "systems/Email delivery.md")

    def test_refuses_to_write_inside_the_vault(self):
        vault = self.tmp / "v"
        shutil.copytree(FREE, vault)
        code, _ = self.run_cli("index", str(vault), "-o", str(vault / "vault-index.json"))
        self.assertEqual(code, 2)
        self.assertFalse((vault / "vault-index.json").exists())

    def test_missing_vault_exits_2(self):
        code, _ = self.run_cli("index", str(self.tmp / "nope"), "-o", str(self.tmp / "out.json"))
        self.assertEqual(code, 2)
        self.assertFalse((self.tmp / "out.json").exists())


class RedactTests(unittest.TestCase):
    def test_mask_basics_and_idempotence(self):
        import redact
        key = "AKIA" + "TESTKEYABCDEMNOP"
        text = f"id {key} mail ana@acme-notes.example aws_secret_access_key = abc/123+x"
        masked = redact.mask(text)
        self.assertEqual(masked, "id AKIA…MNOP mail a***@acme-notes.example aws_secret_access_key = [REDACTED]")
        self.assertEqual(redact.mask(masked), masked)
        self.assertEqual(redact.mask("ASIA" + "TESTKEYABCDEMNOP"), "ASIA…MNOP")

    def test_keep_emails_and_mask_obj(self):
        import redact
        keep = frozenset({"owner@acme-notes.example"})
        obj = {"a": ["owner@acme-notes.example", "other@acme-notes.example"], "SecretAccessKey": "zzz", "n": 3}
        self.assertEqual(redact.mask_obj(obj, keep_emails=keep),
                         {"a": ["owner@acme-notes.example", "o***@acme-notes.example"],
                          "SecretAccessKey": "[REDACTED]", "n": 3})

    def test_secret_label_variants(self):
        import redact
        secret = "wJalrXUtnFEM" + "IK7MDENGbPxRfiCYEXAMPLEKEY"
        for line in (f"**aws_secret_access_key**: {secret}", f"`aws_secret_access_key` = {secret}",
                     f"prod_secret_access_key={secret}", f"AWS_SECRET_ACCESS_KEY_PROD={secret}",
                     f"| Secret Access Key | {secret} |", f"aws_session_token: {secret}",
                     f"AWS_SESSION_TOKEN={secret}", f'{{"SecretAccessKey":"{secret}","x":1}}'):
            masked = redact.mask(line)
            self.assertNotIn(secret, masked, line)
            self.assertIn("[REDACTED]", masked, line)
            self.assertEqual(redact.mask(masked), masked, line)

    def test_access_key_without_word_boundaries(self):
        import redact
        key = "AKIA" + "TESTKEYABCDEMNOP"
        self.assertEqual(redact.mask(f"x{key}"), "xAKIA…MNOP")
        self.assertEqual(redact.mask(f"{key}x"), "AKIA…MNOPx")
        self.assertEqual(redact.mask(f"{key}1"), "AKIA…MNOP1")

    def test_mask_secrets_leaves_emails(self):
        import redact
        self.assertEqual(redact.mask_secrets("ana@acme-notes.example"), "ana@acme-notes.example")

    def test_cli_and_escaped_json_forms(self):
        import redact
        secret = "wJalrXUtnFEM" + "IK7MDENGbPxRfiCYEXAMPLEKEY"
        cases = (f"aws iam x --secret-access-key {secret} --other", f"--secret-access-key={secret}",
                 f"--session-token {secret}", f'{{\\"SecretAccessKey\\":\\"{secret}\\"}}',
                 f"--SECRET-ACCESS-KEY\t{secret}")
        for text in cases:
            masked = redact.mask(text)
            self.assertNotIn(secret, masked, text)
            self.assertIn("[REDACTED]", masked, text)
            self.assertEqual(redact.mask(masked), masked, text)
        self.assertEqual(redact.mask(f"aws x --secret-access-key {secret} --other"),
                         "aws x --secret-access-key [REDACTED] --other")
        self.assertEqual(redact.mask(f'{{\\"SecretAccessKey\\":\\"{secret}\\"}}'),
                         '{\\"SecretAccessKey\\":\\"[REDACTED]\\"}')

    def test_masking_is_linear_on_long_runs(self):
        import redact
        for text in ("a" * 200000, "ab_" * 50000, "0123456789abcdef" * 8000, "secretkey" * 10000,
                     "secret " + " " * 100000, "x@" * 50000):
            start = time.perf_counter()
            redact.mask(text)
            self.assertLess(time.perf_counter() - start, 0.5, text[:12])


if __name__ == "__main__":
    unittest.main()
