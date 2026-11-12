import builtins
import contextlib
import io
import json
import shutil
import tempfile
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


if __name__ == "__main__":
    unittest.main()
