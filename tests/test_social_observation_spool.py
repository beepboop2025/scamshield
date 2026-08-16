import hashlib
import hmac
import json
import stat
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import scamshield.social_observation_spool as social_spool_module
from scamshield.social_observation_spool import (
    LedgerCapacityExceeded,
    LatestCapacityExceeded,
    PublicationCommittedError,
    SocialObservationError,
    SocialObservationSpool,
    TotalCollectionFailure,
    load_social_source_registry,
    publish_export_bundle,
    serialize_versions,
)

UTC = timezone.utc
ROOT = Path(__file__).resolve().parents[1]


def _registry_document(*, extra_source_fields=None, include_instagram=False):
    source = {
        "platform": "telegram",
        "id": "reviewed-publisher",
        "name": "Reviewed Publisher",
        "source_type": "telegram_channel",
        "independence_group": "reviewed-publisher-editorial",
        "article_hosts": ["publisher.example"],
        "collection_policy": "public-or-operator-authorized",
        "rights_policy": "metadata-bounded-excerpt-link-only",
        "telegram_handle": "@publisher_news",
    }
    source.update(extra_source_fields or {})
    sources = [source]
    if include_instagram:
        sources.insert(
            0,
            {
                "id": "instagram-publisher",
                "name": "Instagram Publisher",
                "source_type": "instagram_professional",
                "platform": "instagram",
                "independence_group": "instagram-publisher-editorial",
                "article_hosts": ["instagram-publisher.example"],
                "collection_policy": "public-or-operator-authorized",
                "rights_policy": "metadata-bounded-excerpt-link-only",
            },
        )
    return {
        "schema_version": "palimpsest-social-sources.v1",
        "scope": "bounded-registry-not-global",
        "relation": "attributed-source-report-not-corroboration",
        "sources": sources,
    }


def _source(*, peer_id="-1001234567890", public=True, reference="@publisher_news"):
    return types.SimpleNamespace(
        reference=reference,
        peer_id=peer_id,
        source_key="opaque-monitor-source",
        surface="public_channel" if public else "authorized_private_channel",
        authorization="public" if public else "operator_authorized",
        entity=types.SimpleNamespace(
            username=reference.removeprefix("@"),
            broadcast=True,
            megagroup=False,
        ),
    )


def _message(
    message_id=77,
    *,
    text="Publisher headline https://publisher.example/china/story?utm_source=tg "
    "https://untrusted.example/claim",
    published=None,
    edited=None,
    media=None,
):
    return types.SimpleNamespace(
        id=message_id,
        raw_text=text,
        text=text,
        date=published or datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        edit_date=edited,
        media=media,
        entities=[],
        photo=None,
        video=None,
        audio=None,
        voice=None,
        poll=None,
        document=None,
    )


class SocialRegistryTests(unittest.TestCase):
    def _write(self, directory, document):
        path = Path(directory) / "sources.json"
        path.write_text(json.dumps(document))
        return path

    def test_registry_is_closed_and_requires_public_handles(self):
        with tempfile.TemporaryDirectory() as directory:
            unexpected = _registry_document(extra_source_fields={"token": "secret"})
            with self.assertRaisesRegex(SocialObservationError, "unexpected fields"):
                load_social_source_registry(self._write(directory, unexpected))

            private = _registry_document(
                extra_source_fields={"telegram_handle": "-1001234567890"}
            )
            with self.assertRaisesRegex(SocialObservationError, "public Telegram"):
                load_social_source_registry(self._write(directory, private))

    def test_registry_rejects_duplicate_keys_before_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.json"
            path.write_text(
                '{"schema_version":"palimpsest-social-sources.v1",'
                '"schema_version":"palimpsest-social-sources.v1",'
                '"scope":"bounded-registry-not-global",'
                '"relation":"attributed-source-report-not-corroboration","sources":[]}'
            )
            with self.assertRaisesRegex(SocialObservationError, "duplicate JSON key"):
                load_social_source_registry(path)

    def test_disabled_environment_is_a_noop_without_files(self):
        self.assertIsNone(
            SocialObservationSpool.from_environment(
                {"SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED": "0"}
            )
        )

    def test_enabled_environment_rejects_private_database_override(self):
        with self.assertRaisesRegex(SocialObservationError, "cannot override"):
            SocialObservationSpool.from_environment(
                {
                    "SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED": "1",
                    "SCAMSHIELD_SOCIAL_DB": "/tmp/public.db",
                }
            )

    def test_enabled_environment_rejects_registry_override(self):
        with self.assertRaisesRegex(SocialObservationError, "cannot override"):
            SocialObservationSpool.from_environment(
                {
                    "SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED": "1",
                    "SCAMSHIELD_SOCIAL_SOURCES_FILE": "/tmp/unreviewed.json",
                }
            )

    def test_deployment_registry_matches_eight_source_public_projection(self):
        registry = load_social_source_registry(
            ROOT / "palimpsest-social-sources.example.json"
        )

        self.assertEqual(len(registry.sources), 8)
        self.assertEqual(
            registry.digest,
            "c8abf10569a48107de765794e24b74874d37c788842d1b2616f87f2efffb37ff",
        )
        self.assertEqual(
            [(row.source_id, row.telegram_handle) for row in registry.telegram_sources],
            [("cgtn-telegram", "@cgtnofficial_bj")],
        )


class SocialObservationSpoolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.registry_path = self.root / "sources.json"
        self.registry_path.write_text(json.dumps(_registry_document()))
        self.db_path = self.root / "social.db"
        self.spool = SocialObservationSpool(self.db_path, self.registry_path)
        self.spool.note_monitor_registry(["@publisher_news"])
        self.spool.note_source_available(_source())

    def tearDown(self):
        self.spool.close()
        self.temporary.cleanup()

    def test_double_allowlist_rejects_unregistered_or_private_sources(self):
        unregistered = self.spool.capture(
            _source(reference="@other_news"),
            _message(),
        )
        private = self.spool.capture(_source(public=False), _message())

        self.assertEqual(unregistered.status, "SKIPPED_NOT_DOUBLE_ALLOWLISTED")
        self.assertEqual(private.status, "SKIPPED_NOT_DOUBLE_ALLOWLISTED")
        self.assertEqual(
            self.spool.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
            0,
        )

    def test_capture_requires_current_monitor_allowlist_and_broadcast_entity(self):
        self.spool.note_monitor_registry(["@some_other_source"])
        not_in_monitor = self.spool.capture(_source(), _message())
        self.spool.note_monitor_registry(["@publisher_news"])
        group_source = _source()
        group_source.entity.broadcast = False
        not_broadcast = self.spool.capture(group_source, _message())

        self.assertEqual(not_in_monitor.status, "SKIPPED_NOT_DOUBLE_ALLOWLISTED")
        self.assertEqual(not_broadcast.status, "SKIPPED_NOT_DOUBLE_ALLOWLISTED")
        self.assertEqual(
            self.spool.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
            0,
        )

    def test_collection_error_revokes_capture_until_fresh_io_reattests(self):
        self.spool.note_source_error("@publisher_news", "telegram-read-error")

        with self.assertRaisesRegex(SocialObservationError, "attestation"):
            self.spool.capture(_source(), _message())

        self.assertTrue(self.spool.note_source_available(_source()))
        self.assertEqual(self.spool.capture(_source(), _message()).status, "CAPTURED")

    def test_invalidated_identity_attestation_blocks_export(self):
        with self.spool.conn:
            self.spool.conn.execute(
                "UPDATE source_bindings SET attested = 0 WHERE source_id = ?",
                ("reviewed-publisher",),
            )

        with self.assertRaises(TotalCollectionFailure):
            self.spool.build_export()

    def test_missing_monitor_allowlist_is_reported_as_not_attempted(self):
        self.spool.note_source_available(_source())
        self.spool.note_monitor_registry(["@some_other_source"])

        snapshot, _ = self.spool.build_export(
            generated_at=datetime(2026, 8, 16, 12, 2, tzinfo=UTC)
        )

        self.assertEqual(
            snapshot["coverage"]["receipts"],
            [
                {
                    "source_id": "reviewed-publisher",
                    "platform": "telegram",
                    "status": "not-attempted",
                    "accepted": 0,
                    "rejected": 0,
                    "error_code": None,
                }
            ],
        )

    def test_capture_is_bounded_sanitized_and_filters_article_hosts(self):
        secret_tail = "DO-NOT-PUBLISH-FULL-RAW-CONTENT"
        raw = "A" * 350 + " https://publisher.example/story?utm_campaign=x " + secret_tail
        result = self.spool.capture(
            _source(),
            _message(text=raw),
            collected_at=datetime(2026, 8, 16, 12, 1, tzinfo=UTC),
        )
        snapshot, versions = self.spool.build_export(
            generated_at=datetime(2026, 8, 16, 12, 2, tzinfo=UTC)
        )
        observation = snapshot["observations"][0]

        self.assertEqual(result.status, "CAPTURED")
        self.assertLessEqual(len(observation["title"]), 240)
        self.assertLessEqual(len(observation["excerpt"]), 320)
        self.assertNotIn(secret_tail, json.dumps(snapshot))
        self.assertEqual(observation["relation"], "attributed-source-report-not-corroboration")
        self.assertEqual(observation["content_sha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(observation["permalink"], "https://t.me/publisher_news/77/")
        self.assertEqual(observation["related_urls"], ["https://publisher.example/story"])
        self.assertEqual(len(versions), 1)

        self.assertEqual(
            set(snapshot),
            {
                "schema_version",
                "generated_at",
                "source_registry",
                "source_registry_sha256",
                "scope",
                "relation",
                "coverage",
                "n_observations",
                "observations",
            },
        )
        self.assertEqual(
            set(observation),
            {
                "observation_id",
                "version_id",
                "supersedes_version_id",
                "platform",
                "source_id",
                "source_name",
                "source_type",
                "independence_group",
                "relation",
                "rights_policy",
                "permalink",
                "published_at",
                "first_observed_at",
                "title",
                "excerpt",
                "content_type",
                "content_sha256",
                "state",
                "china_relevance_labels",
                "related_urls",
            },
        )

        public_bytes = json.dumps(snapshot, sort_keys=True)
        self.assertNotIn("native_peer_id", public_bytes)
        self.assertNotIn("native_message_id", public_bytes)
        self.assertNotIn("-1001234567890", public_bytes)
        private_bytes = self.db_path.read_bytes()
        self.assertNotIn(raw.encode(), private_bytes)
        self.assertNotIn(secret_tail.encode(), private_bytes)

    def test_raw_urls_and_url_credentials_never_enter_public_text(self):
        secret = "TOPSECRET-SOCIAL-TOKEN"
        bare_secret = "BARE-DOMAIN-SECRET"
        raw = (
            "Publisher update "
            f"https://publisher.example/china/story?access_token={secret} "
            + "https://"
            + "user:password"
            + "@untrusted.example/private "
            + "www.untrusted.example/also-private"
            + f" publisher.example/private?token={bare_secret}"
        )
        self.spool.capture(_source(), _message(text=raw))
        snapshot, versions = self.spool.build_export()
        public_bytes = json.dumps(
            {"snapshot": snapshot, "versions": versions}, sort_keys=True
        )

        self.assertNotIn(secret, public_bytes)
        self.assertNotIn(bare_secret, public_bytes)
        self.assertNotIn("user:password", public_bytes)
        self.assertNotIn("untrusted.example", public_bytes)
        self.assertEqual(
            snapshot["observations"][0]["related_urls"],
            ["https://publisher.example/china/story"],
        )
        self.assertIn("[link]", snapshot["observations"][0]["title"])
        self.assertNotIn(secret.encode(), self.db_path.read_bytes())
        self.assertNotIn(bare_secret.encode(), self.db_path.read_bytes())

    def test_cjk_adjacent_url_is_redacted_before_publication(self):
        secret = "CJK-ADJACENT-TOKEN"
        raw = f"更新https://publisher.example/story?token={secret}后续"
        self.spool.capture(_source(), _message(text=raw))
        snapshot, versions = self.spool.build_export()
        public_bytes = json.dumps(
            {"snapshot": snapshot, "versions": versions}, sort_keys=True
        )

        self.assertNotIn(secret, public_bytes)
        self.assertEqual(snapshot["observations"][0]["title"], "更新[link]")
        self.assertEqual(
            snapshot["observations"][0]["related_urls"],
            ["https://publisher.example/story"],
        )

    def test_replay_is_idempotent_and_edit_is_append_only(self):
        published = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
        first = self.spool.capture(
            _source(),
            _message(text="Initial post", published=published),
            collected_at=published + timedelta(minutes=1),
        )
        replay = self.spool.capture(
            _source(),
            _message(text="Initial post", published=published),
            collected_at=published + timedelta(minutes=2),
        )
        edited = self.spool.capture(
            _source(),
            _message(
                text="Corrected post",
                published=published,
                edited=published + timedelta(minutes=3),
            ),
            collected_at=published + timedelta(minutes=4),
        )

        self.assertEqual(first.observation_id, replay.observation_id)
        self.assertEqual(first.version_id, replay.version_id)
        self.assertEqual(replay.status, "REPLAYED")
        self.assertEqual(first.observation_id, edited.observation_id)
        self.assertNotEqual(first.version_id, edited.version_id)
        self.assertEqual(
            self.spool.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.spool.conn.execute("SELECT COUNT(*) FROM versions").fetchone()[0],
            2,
        )
        snapshot, versions = self.spool.build_export()
        self.assertEqual(snapshot["observations"][0]["title"], "Corrected post")
        self.assertEqual([row["title"] for row in versions], ["Initial post", "Corrected post"])
        self.assertIsNone(versions[0]["supersedes_version_id"])
        self.assertEqual(versions[1]["supersedes_version_id"], versions[0]["version_id"])
        self.assertEqual(
            {row["schema_version"] for row in versions},
            {"palimpsest-social-observation-version.v1"},
        )
        self.assertEqual(
            self.spool.conn.execute(
                "SELECT native_edited_at FROM versions WHERE version_id = ?",
                (edited.version_id,),
            ).fetchone()[0],
            "2026-08-16T12:03:00Z",
        )

    def test_live_deletion_appends_a_content_free_tombstone(self):
        captured = self.spool.capture(_source(), _message(text="Content to remove"))
        deleted = self.spool.tombstone(_source(), 77)
        snapshot, versions = self.spool.build_export()

        self.assertEqual(deleted.status, "CAPTURED")
        self.assertEqual(deleted.observation_id, captured.observation_id)
        terminal = snapshot["observations"][0]
        self.assertEqual(terminal["state"], "tombstone")
        self.assertEqual(terminal["content_type"], "unavailable")
        self.assertEqual(terminal["title"], "")
        self.assertEqual(terminal["excerpt"], "")
        self.assertEqual(terminal["related_urls"], [])
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[-1]["supersedes_version_id"], captured.version_id)

    def test_delayed_capture_cannot_resurrect_a_tombstoned_message(self):
        published = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
        self.spool.capture(
            _source(), _message(text="Removed content", published=published),
            collected_at=published,
        )
        self.spool.tombstone(
            _source(), 77, collected_at=published + timedelta(minutes=2),
        )

        delayed = self.spool.capture(
            _source(), _message(text="Removed content", published=published),
            collected_at=published + timedelta(minutes=3),
        )
        snapshot, versions = self.spool.build_export()

        self.assertEqual(delayed.status, "SKIPPED_TOMBSTONED")
        self.assertEqual(snapshot["observations"][0]["state"], "tombstone")
        self.assertEqual(len(versions), 2)

    def test_a_b_a_revision_chain_has_distinct_parent_bound_versions(self):
        published = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
        first = self.spool.capture(
            _source(),
            _message(
                message_id=88,
                text="China revision A",
                published=published,
                edited=published + timedelta(minutes=1),
            ),
            collected_at=published + timedelta(minutes=1),
        )
        middle = self.spool.capture(
            _source(),
            _message(
                message_id=88,
                text="China revision B",
                published=published,
                edited=published + timedelta(minutes=2),
            ),
            collected_at=published + timedelta(minutes=2),
        )
        final = self.spool.capture(
            _source(),
            _message(
                message_id=88,
                text="China revision A",
                published=published,
                edited=published + timedelta(minutes=3),
            ),
            collected_at=published + timedelta(minutes=3),
        )
        _snapshot, versions = self.spool.build_export()

        chain = [row for row in versions if row["observation_id"] == first.observation_id]
        self.assertEqual(len(chain), 3)
        self.assertNotEqual(first.version_id, final.version_id)
        self.assertEqual(chain[1]["supersedes_version_id"], first.version_id)
        self.assertEqual(chain[2]["supersedes_version_id"], middle.version_id)

    def test_opaque_high_entropy_url_path_is_rejected_and_query_is_stripped(self):
        opaque = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        jwt = "abcdefgh.ijklmnop.qrstuvwx"
        double_encoded = "".join(f"%25{ord(char):02X}" for char in opaque)
        deeply_encoded = "".join(f"%252525{ord(char):02X}" for char in opaque)
        self.spool.capture(
            _source(),
            _message(
                text=(
                    f"https://publisher.example/download/{opaque} "
                    f"https://publisher.example/download/{jwt} "
                    f"https://publisher.example/download/{double_encoded} "
                    f"https://publisher.example/download/{deeply_encoded} "
                    "https://publisher.example/china/article?session=secret"
                )
            ),
        )
        snapshot, _ = self.spool.build_export()

        self.assertEqual(
            snapshot["observations"][0]["related_urls"],
            ["https://publisher.example/china/article"],
        )

    def test_mixed_cgtn_channel_requires_declared_china_relevance(self):
        document = _registry_document()
        document["sources"][0].update(
            {
                "id": "cgtn-telegram",
                "name": "CGTN",
                "independence_group": "china-media-group-state-media",
                "article_hosts": ["news.cgtn.com", "www.cgtn.com"],
                "telegram_handle": "@CGTNOfficial_BJ",
            }
        )
        path = self.root / "cgtn-sources.json"
        path.write_text(json.dumps(document))
        cgtn = SocialObservationSpool(self.root / "cgtn.db", path)
        source = _source(reference="@CGTNOfficial_BJ")
        try:
            cgtn.note_monitor_registry(["@CGTNOfficial_BJ"])
            cgtn.note_source_available(source)
            football = cgtn.capture(
                source,
                _message(message_id=80, text="Ronaldo scores twice in the final"),
            )
            paraguay = cgtn.capture(
                source,
                _message(message_id=81, text="Paraguay announces its new cabinet"),
            )
            query_smuggling = cgtn.capture(
                source,
                _message(
                    message_id=83,
                    text=(
                        "Ronaldo scores twice "
                        "https://news.cgtn.com/sport/final?campaign=china"
                    ),
                ),
            )
            relevant = cgtn.capture(
                source,
                _message(
                    message_id=82,
                    text=(
                        "China humanoid robot output expands "
                        "https://news.cgtn.com/news/2026-08-16/robot-output"
                    ),
                ),
            )
            snapshot, _ = cgtn.build_export()
        finally:
            cgtn.close()

        self.assertEqual(football.status, "SKIPPED_OUTSIDE_SCOPE")
        self.assertEqual(paraguay.status, "SKIPPED_OUTSIDE_SCOPE")
        self.assertEqual(query_smuggling.status, "SKIPPED_OUTSIDE_SCOPE")
        self.assertEqual(relevant.status, "CAPTURED")
        self.assertEqual(snapshot["n_observations"], 1)
        self.assertEqual(snapshot["coverage"]["rejected"], 3)
        self.assertEqual(snapshot["coverage"]["receipts"][0]["accepted"], 1)

    def test_cgtn_edit_outside_scope_withdraws_prior_terminal(self):
        document = _registry_document()
        document["sources"][0].update(
            {
                "id": "cgtn-telegram",
                "name": "CGTN",
                "independence_group": "china-media-group-state-media",
                "article_hosts": ["news.cgtn.com", "www.cgtn.com"],
                "telegram_handle": "@CGTNOfficial_BJ",
            }
        )
        path = self.root / "cgtn-edit-sources.json"
        path.write_text(json.dumps(document))
        cgtn = SocialObservationSpool(self.root / "cgtn-edit.db", path)
        source = _source(reference="@CGTNOfficial_BJ")
        published = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
        try:
            cgtn.note_monitor_registry(["@CGTNOfficial_BJ"])
            cgtn.note_source_available(source)
            cgtn.capture(
                source,
                _message(
                    message_id=84,
                    text="China humanoid robot output",
                    published=published,
                ),
                collected_at=published,
            )
            outside = cgtn.capture(
                source,
                _message(
                    message_id=84,
                    text="Ronaldo scores twice in the final",
                    published=published,
                    edited=published + timedelta(minutes=1),
                ),
                collected_at=published + timedelta(minutes=1),
            )
            snapshot, versions = cgtn.build_export()
        finally:
            cgtn.close()

        self.assertEqual(outside.status, "SKIPPED_OUTSIDE_SCOPE")
        self.assertEqual(snapshot["observations"][0]["state"], "tombstone")
        self.assertEqual(len(versions), 2)

    def test_private_peer_pin_blocks_handle_reassignment(self):
        with self.assertRaisesRegex(SocialObservationError, "identity pin changed"):
            self.spool.note_source_available(
                _source(peer_id="-100222"),
            )
        self.assertEqual(
            self.spool.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
            0,
        )

    def test_rejected_message_is_counted_without_identity_or_text(self):
        invalid = _message(text="raw content that must not become an error receipt")
        invalid.id = None
        outcome = self.spool.capture(_source(), invalid)
        self.spool.note_source_available(_source())
        snapshot, _ = self.spool.build_export()

        self.assertEqual(outcome.status, "FAILED")
        self.assertEqual(snapshot["coverage"]["rejected"], 1)
        self.assertEqual(
            snapshot["coverage"]["receipts"][0]["status"],
            "success",
        )
        self.assertNotIn("raw content", json.dumps(snapshot))

    def test_atomic_bundle_authenticates_both_streams(self):
        self.spool.capture(
            _source(),
            _message(text="One reviewed update"),
            collected_at=datetime(2026, 8, 16, 12, 1, tzinfo=UTC),
        )
        output = self.root / "export"
        key = "a" * 64
        current = publish_export_bundle(
            self.spool,
            output,
            key,
            generated_at=datetime(2026, 8, 16, 12, 5, tzinfo=UTC),
        )
        self.assertTrue(current.is_symlink())
        self.assertEqual(stat.S_IMODE(current.resolve().stat().st_mode), 0o750)
        self.assertEqual(
            stat.S_IMODE((current / "latest.json").stat().st_mode), 0o640,
        )
        target_before = current.readlink()
        latest = (current / "social-observations-latest.json").read_bytes()
        versions = (current / "social-observations-versions.jsonl").read_bytes()
        signature = json.loads((current / "social-observations.hmac.json").read_text())
        self.assertEqual((current / "latest.json").read_bytes(), latest)
        self.assertEqual((current / "versions.jsonl").read_bytes(), versions)
        self.assertEqual(
            (current / "hmac.json").read_bytes(),
            (current / "social-observations.hmac.json").read_bytes(),
        )
        self.assertNotIn(key, json.dumps(signature))
        for name, content in (
            ("social-observations-latest.json", latest),
            ("social-observations-versions.jsonl", versions),
        ):
            receipt = signature["artifacts"][name]
            self.assertEqual(receipt["sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(
                receipt["hmac_sha256"],
                hmac.new(key.encode(), content, hashlib.sha256).hexdigest(),
            )

        self.spool.note_source_error(
            "@publisher_news",
            "authorization-error",
            observed_at=datetime(2026, 8, 16, 13, 0, tzinfo=UTC),
        )
        with self.assertRaises(TotalCollectionFailure):
            publish_export_bundle(
                self.spool,
                output,
                key,
                generated_at=datetime(2026, 8, 16, 13, 1, tzinfo=UTC),
            )
        self.assertEqual(current.readlink(), target_before)
        self.assertEqual(
            (current / "social-observations-latest.json").read_bytes(),
            latest,
        )

    def test_schema_drift_cannot_replace_last_good_signed_bundle(self):
        self.spool.capture(
            _source(),
            _message(text="Valid signed update"),
            collected_at=datetime(2026, 8, 16, 12, 1, tzinfo=UTC),
        )
        output = self.root / "export"
        current = publish_export_bundle(
            self.spool,
            output,
            "b" * 64,
            generated_at=datetime(2026, 8, 16, 12, 2, tzinfo=UTC),
        )
        target_before = current.readlink()
        latest_before = (current / "social-observations-latest.json").read_bytes()
        encoded = json.loads(
            self.spool.conn.execute("SELECT sanitized_json FROM versions").fetchone()[0]
        )
        encoded["raw_payload"] = "must never be signed"
        with self.spool.conn:
            self.spool.conn.execute(
                "UPDATE versions SET sanitized_json = ?",
                (json.dumps(encoded),),
            )

        with self.assertRaisesRegex(SocialObservationError, "fields changed"):
            publish_export_bundle(
                self.spool,
                output,
                "b" * 64,
                generated_at=datetime(2026, 8, 16, 12, 3, tzinfo=UTC),
            )

        self.assertEqual(current.readlink(), target_before)
        self.assertEqual(
            (current / "social-observations-latest.json").read_bytes(),
            latest_before,
        )

    def test_read_only_exporter_does_not_mutate_spool(self):
        self.spool.capture(_source(), _message(text="Read-only handoff"))
        self.spool.conn.execute("PRAGMA wal_checkpoint(FULL)")
        reader = SocialObservationSpool(
            self.db_path,
            self.registry_path,
            read_only=True,
        )
        try:
            snapshot, versions = reader.build_export()
        finally:
            reader.close()
        self.assertEqual(len(snapshot["observations"]), 1)
        self.assertEqual(len(versions), 1)

    def test_stale_active_source_blocks_export(self):
        stale_db = self.root / "stale.db"
        stale = SocialObservationSpool(
            stale_db,
            self.registry_path,
            max_staleness_seconds=300,
        )
        collected = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
        try:
            stale.note_monitor_registry(["@publisher_news"])
            stale.note_source_available(_source(), observed_at=collected)
            stale.capture(_source(), _message(), collected_at=collected)
            with self.assertRaises(TotalCollectionFailure):
                stale.build_export(generated_at=collected + timedelta(seconds=301))
        finally:
            stale.close()

    def test_in_progress_batch_cannot_publish_partial_freshness(self):
        before = self.spool.conn.execute(
            "SELECT last_success_at FROM coverage WHERE source_id = ?",
            ("reviewed-publisher",),
        ).fetchone()[0]
        started = datetime(2026, 8, 16, 12, 5, tzinfo=UTC)

        self.assertTrue(self.spool.begin_source_batch(_source(), observed_at=started))
        self.spool.capture(
            _source(),
            _message(message_id=93, text="China batch record"),
            collected_at=started,
        )
        during = self.spool.conn.execute(
            "SELECT last_success_at, collection_in_progress FROM coverage "
            "WHERE source_id = ?",
            ("reviewed-publisher",),
        ).fetchone()

        self.assertEqual(during, (before, 1))
        with self.assertRaisesRegex(SocialObservationError, "still in progress"):
            self.spool.build_export(generated_at=started + timedelta(minutes=1))

        self.spool.note_source_available(
            _source(), observed_at=started + timedelta(minutes=2),
        )
        snapshot, _ = self.spool.build_export(
            generated_at=started + timedelta(minutes=3),
        )
        self.assertEqual(snapshot["coverage"]["receipts"][0]["status"], "success")

    def test_recent_live_ids_exclude_terminal_tombstones(self):
        self.spool.capture(_source(), _message(message_id=77, text="China live one"))
        self.spool.capture(_source(), _message(message_id=78, text="China live two"))
        self.spool.tombstone(_source(), 78)

        self.assertEqual(
            self.spool.recent_live_message_ids(_source(), limit=50),
            (77,),
        )

    def test_ledger_cap_rejects_before_append_and_marks_source_failed(self):
        self.spool.capture(_source(), _message(message_id=77, text="China first"))
        current_size = self.spool._ledger_serialized_size()
        _latest, ledger = self.spool.build_export()
        self.assertEqual(current_size, len(serialize_versions(ledger)))
        versions_before = self.spool.conn.execute(
            "SELECT COUNT(*) FROM versions"
        ).fetchone()[0]

        with mock.patch.object(
            social_spool_module, "MAX_LEDGER_BYTES", current_size,
        ):
            with self.assertRaises(LedgerCapacityExceeded):
                self.spool.capture(
                    _source(), _message(message_id=78, text="China overflow"),
                )

        self.assertEqual(
            self.spool.conn.execute("SELECT COUNT(*) FROM versions").fetchone()[0],
            versions_before,
        )
        self.assertEqual(
            self.spool.conn.execute(
                "SELECT current_status, last_error_code FROM coverage "
                "WHERE source_id = ?",
                ("reviewed-publisher",),
            ).fetchone(),
            ("failure", "ledger-capacity-error"),
        )

    def test_latest_cap_rejects_before_append_and_marks_source_failed(self):
        self.spool.capture(_source(), _message(message_id=77, text="China first"))
        current_size = self.spool._latest_payload_serialized_size()
        versions_before = self.spool.conn.execute(
            "SELECT COUNT(*) FROM versions"
        ).fetchone()[0]

        with mock.patch.object(
            social_spool_module, "MAX_LATEST_PAYLOAD_BYTES", current_size,
        ):
            with self.assertRaises(LatestCapacityExceeded):
                self.spool.capture(
                    _source(), _message(message_id=78, text="China overflow"),
                )

        self.assertEqual(
            self.spool.conn.execute("SELECT COUNT(*) FROM versions").fetchone()[0],
            versions_before,
        )
        self.assertEqual(
            self.spool.conn.execute(
                "SELECT current_status, last_error_code FROM coverage "
                "WHERE source_id = ?",
                ("reviewed-publisher",),
            ).fetchone(),
            ("failure", "latest-capacity-error"),
        )

    def test_latest_cap_allows_a_terminal_tombstone_to_shrink_view(self):
        self.spool.capture(
            _source(),
            _message(message_id=77, text="China " + "long report " * 20),
        )
        current_size = self.spool._latest_payload_serialized_size()

        with mock.patch.object(
            social_spool_module, "MAX_LATEST_PAYLOAD_BYTES", current_size,
        ):
            result = self.spool.tombstone(_source(), 77)

        self.assertEqual(result.status, "CAPTURED")
        self.assertLess(self.spool._latest_payload_serialized_size(), current_size)

    def test_registry_retirement_with_history_fails_closed(self):
        self.spool.capture(_source(), _message())
        self.registry_path.write_text(
            json.dumps(
                {
                    "schema_version": "palimpsest-social-sources.v1",
                    "scope": "bounded-registry-not-global",
                    "relation": "attributed-source-report-not-corroboration",
                    "sources": [],
                }
            )
        )
        self.spool.reload_registry()

        with self.assertRaisesRegex(SocialObservationError, "retired registry source"):
            self.spool.build_export()

    def test_registry_identity_change_fails_closed_even_without_observations(self):
        changed = _registry_document()
        changed["sources"][0]["telegram_handle"] = "@renamed_news"
        self.registry_path.write_text(json.dumps(changed))
        self.spool.reload_registry()

        with self.assertRaisesRegex(SocialObservationError, "identity binding"):
            self.spool.build_export()

    def test_generation_retention_is_bounded(self):
        self.spool.capture(_source(), _message())
        output = self.root / "bounded-export"
        start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
        for offset in range(7):
            publish_export_bundle(
                self.spool,
                output,
                "r" * 64,
                generated_at=start + timedelta(minutes=offset),
            )
        generations = [
            item
            for item in (output / "generations").iterdir()
            if item.is_dir() and not item.is_symlink()
        ]
        self.assertLessEqual(len(generations), 4)
        self.assertTrue((output / "current" / "latest.json").is_file())

    def test_post_commit_pruning_failure_does_not_report_publication_failure(self):
        self.spool.capture(_source(), _message())
        output = self.root / "cleanup-failure-export"

        with mock.patch(
            "scamshield.social_observation_spool._prune_generations",
            side_effect=OSError("simulated cleanup failure"),
        ):
            current = publish_export_bundle(
                self.spool,
                output,
                "p" * 64,
                generated_at=datetime(2026, 8, 16, 12, 4, tzinfo=UTC),
            )

        self.assertTrue(current.is_symlink())
        self.assertTrue((current / "latest.json").is_file())

    def test_post_switch_fsync_failure_reports_committed_state(self):
        self.spool.capture(_source(), _message())
        output = self.root / "commit-fsync-export"
        real_fsync = social_spool_module._fsync_directory

        def fail_root_only(path):
            if Path(path) == output:
                raise OSError("simulated root fsync failure")
            return real_fsync(path)

        with mock.patch(
            "scamshield.social_observation_spool._fsync_directory",
            side_effect=fail_root_only,
        ):
            with self.assertRaises(PublicationCommittedError):
                publish_export_bundle(
                    self.spool,
                    output,
                    "f" * 64,
                    generated_at=datetime(2026, 8, 16, 12, 4, tzinfo=UTC),
                )

        self.assertTrue((output / "current").is_symlink())
        self.assertTrue((output / "current" / "latest.json").is_file())

    def test_export_refuses_symlinked_generation_parent(self):
        self.spool.capture(_source(), _message())
        output = self.root / "unsafe-export"
        output.mkdir()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (output / "generations").symlink_to(elsewhere, target_is_directory=True)

        with self.assertRaisesRegex(SocialObservationError, "real directory"):
            publish_export_bundle(self.spool, output, "s" * 64)

    def test_export_refuses_mutated_content_addressed_generation(self):
        self.spool.capture(_source(), _message())
        output = self.root / "immutable-export"
        generated = datetime(2026, 8, 16, 12, 2, tzinfo=UTC)
        current = publish_export_bundle(
            self.spool, output, "i" * 64, generated_at=generated,
        )
        (current / "latest.json").write_bytes(b"x")

        with self.assertRaisesRegex(SocialObservationError, "not immutable"):
            publish_export_bundle(
                self.spool, output, "i" * 64, generated_at=generated,
            )

    def test_private_spool_contains_native_identity_without_raw_message(self):
        raw = "Short public excerpt and " + "private-rest-" * 50
        self.spool.capture(_source(), _message(message_id=91, text=raw))
        row = self.spool.conn.execute(
            "SELECT native_peer_id, native_message_id FROM observations"
        ).fetchone()
        self.assertEqual(row, ("-1001234567890", 91))
        encoded_versions = "\n".join(
            row[0]
            for row in self.spool.conn.execute("SELECT sanitized_json FROM versions")
        )
        self.assertNotIn(raw, encoded_versions)

    def test_ids_mirror_palimpsest_canonical_hash_algorithm(self):
        result = self.spool.capture(
            _source(),
            _message(text="Canonical identity check"),
            collected_at=datetime(2026, 8, 16, 12, 1, tzinfo=UTC),
        )
        snapshot, _versions = self.spool.build_export(
            generated_at=datetime(2026, 8, 16, 12, 2, tzinfo=UTC)
        )
        observation = snapshot["observations"][0]
        identity_payload = {
            "platform": "telegram",
            "source_id": "reviewed-publisher",
            "native_id": "-1001234567890:77",
        }
        expected_observation = "social-" + hashlib.sha256(
            json.dumps(
                identity_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()[:32]
        version_payload = {
            key: value
            for key, value in observation.items()
            if key not in {"version_id", "first_observed_at"}
        }
        expected_version = "socialv-" + hashlib.sha256(
            json.dumps(
                version_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()[:32]
        self.assertEqual(result.observation_id, expected_observation)
        self.assertEqual(result.version_id, expected_version)

    def test_local_handle_is_excluded_from_complete_public_registry_digest(self):
        document = _registry_document(include_instagram=True)
        path = self.root / "complete-sources.json"
        path.write_text(json.dumps(document))
        registry = load_social_source_registry(path)
        public_document = json.loads(json.dumps(document))
        public_document["sources"][1].pop("telegram_handle")
        expected = hashlib.sha256(
            json.dumps(
                public_document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self.assertEqual(registry.digest, expected)
        self.assertEqual(len(registry.sources), 2)
        self.assertEqual(len(registry.telegram_sources), 1)

        alternate_db = self.root / "complete.db"
        alternate = SocialObservationSpool(alternate_db, path)
        try:
            alternate.note_source_available(_source())
            snapshot, _ = alternate.build_export(
                generated_at=datetime(2026, 8, 16, 12, 2, tzinfo=UTC)
            )
        finally:
            alternate.close()
        self.assertEqual(snapshot["coverage"]["configured"], 2)
        self.assertEqual(
            snapshot["coverage"]["receipts"][0],
            {
                "source_id": "instagram-publisher",
                "platform": "instagram",
                "status": "not-attempted",
                "accepted": 0,
                "rejected": 0,
                "error_code": None,
            },
        )

    def test_hardened_export_timer_is_opt_in_and_networkless(self):
        unit = (
            ROOT / "deploy/hetzner/scamshield-social-export.service"
        ).read_text()
        timer = (
            ROOT / "deploy/hetzner/scamshield-social-export.timer"
        ).read_text()
        environment = (
            ROOT / "deploy/hetzner/scamshield.env.example"
        ).read_text()
        preflight = (ROOT / "deploy/hetzner/preflight.sh").read_text()

        self.assertIn("PrivateNetwork=true", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn(
            "ReadWritePaths=/var/lib/scamshield/social-export",
            unit,
        )
        self.assertNotIn("SCAMSHIELD_SOCIAL_EXPORT_HMAC_KEY=", unit)
        self.assertIn(
            "LoadCredential=social_export_hmac:"
            "/etc/scamshield/social-export-hmac.key",
            unit,
        )
        self.assertIn("UnsetEnvironment=SCAMSHIELD_TOKEN", unit)
        self.assertIn("InaccessiblePaths=/var/lib/scamshield/telegram", unit)
        self.assertIn("InaccessiblePaths=/etc/scamshield/scamshield.env", unit)
        self.assertNotIn("ConditionPathExists=", unit)
        self.assertIn("Persistent=true", timer)
        self.assertIn("SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED=0", environment)
        self.assertNotIn("SCAMSHIELD_SOCIAL_DB=", environment)
        self.assertIn("social-export", preflight)


if __name__ == "__main__":
    unittest.main()
