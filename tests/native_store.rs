use std::fs;

use square_unifi_protect::{
    AppError, Store,
    models::{CameraMappingEntry, PaymentFacts},
    store::{
        ALARM_ENABLED_AFTER_SETTING, ROLE_ADMIN, ROLE_VIEWER, normalize_username,
        validate_camera_id,
    },
};

const CAMERA_A: &str = "cam1aaaaaaaaaaaaaaaaaaaa";
const CAMERA_B: &str = "cam2bbbbbbbbbbbbbbbbbbbb";
const BASE_TS: i64 = 1_800_000_000_000;

fn payment(id: &str, offset_ms: i64) -> PaymentFacts {
    PaymentFacts {
        id: id.into(),
        created_at: "2027-01-15T08:00:00.000Z".into(),
        ts_ms: BASE_TS + offset_ms,
        updated_at: "2027-01-15T08:00:00.000Z".into(),
        updated_ts_ms: BASE_TS + offset_ms,
        amount: 99,
        currency: "USD".into(),
        refunded_amount: 0,
        status: "COMPLETED".into(),
        location_id: "LOC_1".into(),
        device_id: "DEVICE_1".into(),
        device_name: "Register One".into(),
        card_last4: "4242".into(),
        receipt_url: "https://square.example/receipt".into(),
    }
}

fn mapping(location: &str, device: &str, camera: &str) -> CameraMappingEntry {
    CameraMappingEntry {
        location_id: location.into(),
        device_id: device.into(),
        device_name: if device.is_empty() {
            String::new()
        } else {
            "Register".into()
        },
        camera_id: camera.into(),
        camera_name: "Counter".into(),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn new_store_is_private_complete_and_reopenable() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    assert!(!store.setup_complete().unwrap());
    assert!(temp.path().join("spi.db").is_file());
    assert!(store.thumbnail_dir().is_dir());
    drop(store);
    assert!(!Store::open(temp.path()).unwrap().setup_complete().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(temp.path()).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            fs::metadata(temp.path().join("spi.db"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}

#[test]
fn secret_settings_roundtrip_encrypted_and_delete_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let secret = "unique-plaintext-credential-never-on-disk";
    store
        .update_settings(
            &[
                ("square.access_token", secret, true),
                ("square.environment", "sandbox", false),
            ],
            &[],
        )
        .unwrap();
    assert_eq!(
        store.get_setting("square.access_token").unwrap().as_deref(),
        Some(secret)
    );
    assert_eq!(
        store.get_setting("square.environment").unwrap().as_deref(),
        Some("sandbox")
    );
    for entry in fs::read_dir(temp.path()).unwrap().filter_map(Result::ok) {
        if entry.file_type().unwrap().is_file() {
            let bytes = fs::read(entry.path()).unwrap();
            assert!(
                !contains_bytes(&bytes, secret.as_bytes()),
                "plaintext in {:?}",
                entry.path()
            );
        }
    }
    store
        .update_settings(
            &[("square.environment", "production", false)],
            &["square.access_token"],
        )
        .unwrap();
    assert_eq!(store.get_setting("square.access_token").unwrap(), None);
    assert_eq!(
        store.get_setting("square.environment").unwrap().as_deref(),
        Some("production")
    );
}

#[test]
fn oauth_states_are_single_use_clearable_and_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    store.store_oauth_state("single").unwrap();
    assert!(store.consume_oauth_state("single").unwrap());
    assert!(!store.consume_oauth_state("single").unwrap());
    for index in 0..20 {
        store.store_oauth_state(&format!("state-{index}")).unwrap();
    }
    let retained = (0..20)
        .filter(|index| {
            store
                .consume_oauth_state(&format!("state-{index}"))
                .unwrap()
        })
        .count();
    assert_eq!(retained, 16);
    store.store_oauth_state("clear-me").unwrap();
    store.clear_oauth_states().unwrap();
    assert!(!store.consume_oauth_state("clear-me").unwrap());
}

#[test]
fn initial_admin_has_one_atomic_winner() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let handles: Vec<_> = (0..8)
        .map(|index| {
            let store = store.clone();
            std::thread::spawn(move || {
                store
                    .create_initial_admin(&format!("hash-{index}"))
                    .unwrap()
            })
        })
        .collect();
    let winners = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|winner| *winner)
        .count();
    assert_eq!(winners, 1);
    assert!(store.setup_complete().unwrap());
    assert_eq!(store.list_users().unwrap().len(), 1);
    assert_eq!(store.list_users().unwrap()[0].username, "admin");
}

#[test]
fn username_and_role_validation_are_case_insensitive_and_bounded() {
    for (input, expected) in [
        ("admin", "admin"),
        (" Audit.Viewer ", "Audit.Viewer"),
        ("user-name_2", "user-name_2"),
    ] {
        assert_eq!(normalize_username(input).unwrap(), expected);
    }
    for input in ["", ".hidden", "-dash", "space name", "slash/name", "💳"] {
        assert!(matches!(
            normalize_username(input),
            Err(AppError::Unprocessable(_))
        ));
    }
    assert!(matches!(
        normalize_username(&"x".repeat(65)),
        Err(AppError::Unprocessable(_))
    ));

    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let viewer = store
        .create_user("Audit.Viewer", "hash", ROLE_VIEWER)
        .unwrap();
    assert_eq!(viewer.role, ROLE_VIEWER);
    assert!(matches!(
        store.create_user("audit.viewer", "hash", ROLE_ADMIN),
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        store.create_user("another", "hash", "owner"),
        Err(AppError::Unprocessable(_))
    ));
}

#[test]
fn password_reset_revokes_sessions_and_fences_stale_logins() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let user = store
        .create_user("viewer", "old-hash", ROLE_VIEWER)
        .unwrap();
    let login = store.user_for_login("VIEWER").unwrap().unwrap();
    store
        .create_session("session-one", user.id, login.auth_revision, "10.0.0.5")
        .unwrap();
    store
        .create_session("session-two", user.id, login.auth_revision, "10.0.0.6")
        .unwrap();
    assert!(store.session_user("session-one").unwrap().is_some());
    let (_, revoked) = store
        .reset_user_password(user.id, "new-hash")
        .unwrap()
        .unwrap();
    assert_eq!(revoked, 2);
    assert!(store.session_user("session-one").unwrap().is_none());
    assert!(matches!(
        store.create_session("stale", user.id, login.auth_revision, "10.0.0.7"),
        Err(AppError::Conflict(_))
    ));
    assert_eq!(
        store
            .user_for_login("viewer")
            .unwrap()
            .unwrap()
            .password_hash,
        "new-hash"
    );
}

#[test]
fn login_audit_is_paginated_newest_first_and_session_delete_is_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let user = store.create_user("viewer", "hash", ROLE_VIEWER).unwrap();
    let revision = store
        .user_for_login("viewer")
        .unwrap()
        .unwrap()
        .auth_revision;
    for index in 0..5 {
        store
            .create_session(
                &format!("token-{index}"),
                user.id,
                revision,
                &format!("10.0.0.{index}"),
            )
            .unwrap();
    }
    let (first, cursor) = store.list_login_audit(2, None).unwrap();
    assert_eq!(first.len(), 2);
    assert!(first[0].id > first[1].id);
    assert_eq!(first[0].username, "viewer");
    let (second, _) = store.list_login_audit(2, cursor).unwrap();
    assert_eq!(second.len(), 2);
    assert!(
        first
            .iter()
            .all(|left| second.iter().all(|right| left.id != right.id))
    );
    for invalid in [0, 251] {
        assert!(matches!(
            store.list_login_audit(invalid, None),
            Err(AppError::Unprocessable(_))
        ));
    }
    store.delete_session("token-0").unwrap();
    assert!(store.session_user("token-0").unwrap().is_none());
    assert!(store.session_user("token-1").unwrap().is_some());
}

#[test]
fn camera_ids_and_mapping_sets_are_strict_and_transactional() {
    for valid in ["abc123", CAMERA_A, "A1A1A1"] {
        validate_camera_id(valid).unwrap();
    }
    for invalid in ["", "../etc", "a b", "a/b", "cam?ts=1"] {
        assert!(matches!(
            validate_camera_id(invalid),
            Err(AppError::Unprocessable(_))
        ));
    }
    assert!(matches!(
        validate_camera_id(&"x".repeat(65)),
        Err(AppError::Unprocessable(_))
    ));

    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let initial = mapping("LOC_1", "", CAMERA_A);
    store
        .replace_camera_mappings(std::slice::from_ref(&initial))
        .unwrap();
    let duplicate = vec![initial.clone(), initial.clone()];
    assert!(matches!(
        store.replace_camera_mappings(&duplicate),
        Err(AppError::Unprocessable(_))
    ));
    assert_eq!(store.get_camera_mappings().unwrap().len(), 1);
    let too_many = (0..501)
        .map(|index| mapping(&format!("LOC_{index}"), "", CAMERA_A))
        .collect::<Vec<_>>();
    assert!(matches!(
        store.replace_camera_mappings(&too_many),
        Err(AppError::Unprocessable(_))
    ));
    assert_eq!(store.get_camera_mappings().unwrap().len(), 1);
}

#[test]
fn device_mapping_precedes_location_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    store
        .replace_camera_mappings(&[
            mapping("LOC_1", "", CAMERA_A),
            mapping("LOC_1", "DEVICE_1", CAMERA_B),
        ])
        .unwrap();
    assert_eq!(
        store
            .camera_for_location("LOC_1", "DEVICE_1")
            .unwrap()
            .unwrap()
            .camera_id,
        CAMERA_B
    );
    assert_eq!(
        store
            .camera_for_location("LOC_1", "DEVICE_2")
            .unwrap()
            .unwrap()
            .camera_id,
        CAMERA_A
    );
    assert!(
        store
            .camera_for_location("LOC_2", "DEVICE_1")
            .unwrap()
            .is_none()
    );
}

#[test]
fn payment_updates_are_newest_wins_sparse_safe_and_refund_monotonic() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut original = payment("PAY_UPDATE", 0);
    original.status = "PENDING".into();
    original.refunded_amount = 25;
    assert!(store.upsert_payment(&original).unwrap());

    let mut newer = original.clone();
    newer.updated_ts_ms += 60_000;
    newer.updated_at = "2027-01-15T08:01:00.000Z".into();
    newer.status = "COMPLETED".into();
    newer.amount = 109;
    newer.refunded_amount = 10;
    newer.device_id.clear();
    newer.device_name.clear();
    assert!(!store.upsert_payment(&newer).unwrap());
    let stored = store.get_transaction("PAY_UPDATE").unwrap().unwrap();
    assert_eq!(stored.status, "COMPLETED");
    assert_eq!(stored.amount, 109);
    assert_eq!(stored.refunded_amount, 25);
    assert_eq!(stored.device_id, "DEVICE_1");
    assert_eq!(stored.device_name, "Register One");

    let mut stale = original;
    stale.amount = 1;
    stale.status = "FAILED".into();
    assert!(!store.upsert_payment(&stale).unwrap());
    let stored = store.get_transaction("PAY_UPDATE").unwrap().unwrap();
    assert_eq!(stored.amount, 109);
    assert_eq!(stored.status, "COMPLETED");
}

#[test]
fn poll_watermarks_are_location_scoped_monotonic_and_nonnegative() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    assert_eq!(store.square_poll_watermark("LOC_A").unwrap(), None);
    store.advance_square_poll_watermark("LOC_A", 2_000).unwrap();
    store.advance_square_poll_watermark("LOC_A", 1_000).unwrap();
    store.advance_square_poll_watermark("LOC_B", 3_000).unwrap();
    assert_eq!(store.square_poll_watermark("LOC_A").unwrap(), Some(2_000));
    assert_eq!(store.square_poll_watermark("LOC_B").unwrap(), Some(3_000));
    assert!(matches!(
        store.advance_square_poll_watermark("LOC_A", -1),
        Err(AppError::Unprocessable(_))
    ));
}

#[test]
fn transaction_pages_are_stable_filter_bound_and_validate_limits() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    for index in 0..6 {
        let mut item = payment(&format!("PAY_{index}"), index * 1_000);
        item.status = if index % 2 == 0 {
            "COMPLETED"
        } else {
            "PENDING"
        }
        .into();
        store.upsert_payment(&item).unwrap();
    }
    let (first, snapshot) = store.list_transactions_page(2, 0, None, "", "").unwrap();
    assert_eq!(first.len(), 2);
    store.upsert_payment(&payment("PAY_NEW", 60_000)).unwrap();
    let (second, same_snapshot) = store
        .list_transactions_page(2, 2, Some(snapshot), "", "")
        .unwrap();
    assert_eq!(same_snapshot, snapshot);
    assert!(
        first
            .iter()
            .all(|left| second.iter().all(|right| left.id != right.id))
    );
    assert!(matches!(
        store.list_transactions_page(2, 0, Some(snapshot), "", "COMPLETED"),
        Err(AppError::Conflict(_))
    ));
    for (limit, offset) in [(0, 0), (501, 0), (1, -1), (1, 1_000_001)] {
        assert!(matches!(
            store.list_transactions_page(limit, offset, None, "", ""),
            Err(AppError::Unprocessable(_))
        ));
    }
}

#[test]
fn notes_are_revision_fenced_idempotent_and_searchable_as_literal_text() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    store.upsert_payment(&payment("PAY_NOTE", 0)).unwrap();
    let (note, revision) = store
        .set_transaction_note("PAY_NOTE", "Door issue 100%_literal", 0)
        .unwrap()
        .unwrap();
    assert_eq!(note, "Door issue 100%_literal");
    assert_eq!(revision, 1);
    assert_eq!(
        store
            .set_transaction_note("PAY_NOTE", "Door issue 100%_literal", revision)
            .unwrap()
            .unwrap()
            .1,
        revision
    );
    assert!(matches!(
        store.set_transaction_note("PAY_NOTE", "stale", 0),
        Err(AppError::Conflict(_))
    ));
    let (matches, _) = store
        .list_transactions_page(50, 0, None, "100%_literal", "")
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, "PAY_NOTE");
    assert!(matches!(
        store.set_transaction_note("PAY_NOTE", &"x".repeat(2001), revision),
        Err(AppError::Unprocessable(_))
    ));
}

#[test]
fn webhook_receipts_dedupe_and_never_regress_freshness() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    store
        .update_settings(
            &[
                ("square.webhook_signature_key", "key", true),
                (
                    "square.webhook_url",
                    "https://example.test/webhooks/square",
                    false,
                ),
            ],
            &[],
        )
        .unwrap();
    store.record_webhook_delivery(2_000).unwrap();
    store.record_webhook_delivery(1_000).unwrap();
    let newest = "a".repeat(64);
    let older = "b".repeat(64);
    assert!(
        store
            .record_webhook_receipt(&newest, "payment.updated", 2_000, Some(1_500))
            .unwrap()
    );
    assert!(
        !store
            .record_webhook_receipt(&newest, "payment.updated", 2_000, Some(1_500))
            .unwrap()
    );
    assert!(
        store
            .record_webhook_receipt(&older, "payment.created", 1_000, Some(900))
            .unwrap()
    );
    let metrics = store.webhook_metrics().unwrap();
    assert_eq!(metrics["configured"], true);
    assert_eq!(metrics["delivery_count"], 2);
    assert_eq!(metrics["last_event_ms"], 2_000);
    assert_eq!(metrics["last_payment_ms"], 2_000);
    assert_eq!(metrics["last_delivery_lag_ms"], 500);
    assert_eq!(metrics["accepted_payment_count"], 2);
    assert_eq!(metrics["duplicate_count"], 1);
    for invalid in [String::new(), "A".repeat(64), "f".repeat(63)] {
        assert!(matches!(
            store.record_webhook_receipt(&invalid, "payment.updated", 1, None),
            Err(AppError::Unprocessable(_))
        ));
    }
}

#[test]
fn motion_token_rotates_dedupes_and_moves_pending_to_flagged() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (config, first) = store
        .configure_motion(CAMERA_A, "Checkout Camera", 15, 90, 30, false)
        .unwrap();
    let first = first.unwrap();
    assert!(config.enabled);
    assert!(store.authenticate_motion(&first).is_ok());
    let (_, not_revealed) = store
        .configure_motion(CAMERA_A, "Checkout Camera", 15, 90, 30, false)
        .unwrap();
    assert!(not_revealed.is_none());
    assert!(
        store
            .record_motion(
                &first,
                "event-one",
                BASE_TS,
                BASE_TS,
                "post",
                "Register motion",
                &[" sensor-1 ".into(), "sensor-1".into()],
            )
            .unwrap()
    );
    assert!(
        !store
            .record_motion(
                &first,
                "event-one",
                BASE_TS,
                BASE_TS,
                "post",
                "Register motion",
                &[],
            )
            .unwrap()
    );
    let pending = store.motion_alerts(50, true, BASE_TS + 89_999).unwrap();
    assert_eq!(pending[0].state, "pending");
    assert_eq!(pending[0].device_identifiers, ["sensor-1"]);
    let flagged = store.motion_alerts(50, true, BASE_TS + 90_000).unwrap();
    assert_eq!(flagged[0].state, "flagged");
    assert_eq!(store.motion_config().unwrap().last_event_ms, Some(BASE_TS));

    let (_, rotated) = store
        .configure_motion(CAMERA_B, "Other camera", 15, 90, 30, false)
        .unwrap();
    assert!(rotated.is_some());
    assert!(matches!(
        store.authenticate_motion(&first),
        Err(AppError::Unauthorized(_))
    ));
    store.disable_motion().unwrap();
    assert!(!store.motion_config().unwrap().enabled);
}

#[test]
fn motion_configuration_and_event_inputs_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    for (window, grace, retention) in [
        (0, 90, 30),
        (301, 90, 30),
        (15, -1, 30),
        (15, 601, 30),
        (15, 90, 0),
        (15, 90, 366),
    ] {
        assert!(matches!(
            store.configure_motion(CAMERA_A, "Camera", window, grace, retention, false),
            Err(AppError::Unprocessable(_))
        ));
    }
    let (_, token) = store
        .configure_motion(CAMERA_A, "Camera", 15, 0, 1, false)
        .unwrap();
    let token = token.unwrap();
    for (key, method, event_ts, received) in [
        ("", "post", BASE_TS, BASE_TS),
        ("event", "put", BASE_TS, BASE_TS),
        ("event", "post", -1, BASE_TS),
        ("event", "post", BASE_TS, -1),
    ] {
        assert!(matches!(
            store.record_motion(&token, key, event_ts, received, method, "motion", &[]),
            Err(AppError::Unprocessable(_))
        ));
    }
}

#[test]
fn alarm_claims_are_exclusive_token_fenced_and_releasable() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    store
        .set_setting(ALARM_ENABLED_AFTER_SETTING, "0", false)
        .unwrap();
    store.upsert_payment(&payment("PAY_ALARM", 0)).unwrap();
    assert_eq!(
        store.pending_alarm_ids(10).unwrap(),
        vec!["PAY_ALARM".to_owned()]
    );
    let claim = store.claim_alarm_trigger("PAY_ALARM").unwrap().unwrap();
    assert!(store.claim_alarm_trigger("PAY_ALARM").unwrap().is_none());
    assert!(
        !store
            .release_alarm_claim("PAY_ALARM", "wrong-token")
            .unwrap()
    );
    assert!(store.release_alarm_claim("PAY_ALARM", &claim).unwrap());
    assert!(store.claim_alarm_trigger("PAY_ALARM").unwrap().is_some());
}

#[test]
fn square_account_clear_removes_scoped_rows_watermarks_and_thumbnail_files() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    store
        .replace_camera_mappings(&[mapping("LOC_1", "", CAMERA_A)])
        .unwrap();
    store.upsert_payment(&payment("PAY_CLEAR", 0)).unwrap();
    store
        .advance_square_poll_watermark("LOC_1", BASE_TS)
        .unwrap();
    store
        .record_webhook_receipt(&"c".repeat(64), "payment.created", BASE_TS, None)
        .unwrap();
    fs::write(store.thumbnail_dir().join("orphan.jpg"), b"bytes").unwrap();
    store.clear_square_account_data().unwrap();
    assert!(store.get_transaction("PAY_CLEAR").unwrap().is_none());
    assert!(store.get_camera_mappings().unwrap().is_empty());
    assert_eq!(store.square_poll_watermark("LOC_1").unwrap(), None);
    assert!(!store.webhook_receipt_exists(&"c".repeat(64)).unwrap());
    assert_eq!(fs::read_dir(store.thumbnail_dir()).unwrap().count(), 0);
}

#[test]
fn square_account_save_rolls_back_records_credentials_and_oauth_state_together() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    store
        .replace_camera_mappings(&[mapping("LOC_1", "", CAMERA_A)])
        .unwrap();
    store.upsert_payment(&payment("PAY_OLD", 0)).unwrap();
    store
        .advance_square_poll_watermark("LOC_1", BASE_TS)
        .unwrap();
    store
        .record_webhook_receipt(&"c".repeat(64), "payment.created", BASE_TS, None)
        .unwrap();
    store
        .update_settings(
            &[
                ("square.access_token", "test-old-access", true),
                ("square.environment", "sandbox", false),
                ("square.webhook_signature_key", "test-old-key", true),
            ],
            &[],
        )
        .unwrap();
    store.store_oauth_state("test-state").unwrap();
    let image = store.thumbnail_dir().join("old.jpg");
    fs::write(&image, b"old image").unwrap();
    let connection = rusqlite::Connection::open(temp.path().join("spi.db")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_account_save BEFORE DELETE ON square_oauth_states \
             BEGIN SELECT RAISE(ABORT, 'injected database failure'); END;",
        )
        .unwrap();
    let result = {
        let _guard = store.integration_guard(true).unwrap();
        store.save_square_account_under_guard(
            &[
                ("square.access_token", "test-new-access", true),
                ("square.environment", "production", false),
            ],
            &[],
            true,
        )
    };
    assert!(result.is_err());
    assert!(store.get_transaction("PAY_OLD").unwrap().is_some());
    assert_eq!(store.get_camera_mappings().unwrap().len(), 1);
    assert_eq!(store.square_poll_watermark("LOC_1").unwrap(), Some(BASE_TS));
    assert!(store.webhook_receipt_exists(&"c".repeat(64)).unwrap());
    assert_eq!(
        store.webhook_metrics().unwrap()["accepted_payment_count"],
        1
    );
    assert_eq!(
        store.get_setting("square.access_token").unwrap().as_deref(),
        Some("test-old-access")
    );
    assert_eq!(
        store.get_setting("square.environment").unwrap().as_deref(),
        Some("sandbox")
    );
    assert_eq!(
        store
            .get_setting("square.webhook_signature_key")
            .unwrap()
            .as_deref(),
        Some("test-old-key")
    );
    assert!(!store.orphan_thumbnail_cleanup_pending().unwrap());
    assert!(image.exists());
    connection
        .execute_batch("DROP TRIGGER fail_account_save")
        .unwrap();
    assert!(store.consume_oauth_state("test-state").unwrap());
}

#[test]
fn square_cleanup_survives_restart_and_preserves_new_account_thumbnails() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    fs::write(store.thumbnail_dir().join("old.jpg"), b"old image").unwrap();
    let displaced = temp.path().join("saved-thumbnails");
    fs::rename(store.thumbnail_dir(), &displaced).unwrap();
    fs::write(store.thumbnail_dir(), b"not a directory").unwrap();
    {
        let _guard = store.integration_guard(true).unwrap();
        assert!(
            store
                .save_square_account_under_guard(
                    &[("square.access_token", "test-new-access", true)],
                    &[],
                    true,
                )
                .unwrap()
        );
    }
    fs::remove_file(store.thumbnail_dir()).unwrap();
    fs::rename(&displaced, store.thumbnail_dir()).unwrap();
    drop(store);
    let store = Store::open(temp.path()).unwrap();
    assert!(store.orphan_thumbnail_cleanup_pending().unwrap());
    assert_eq!(
        store.get_setting("square.access_token").unwrap().as_deref(),
        Some("test-new-access")
    );
    store
        .replace_camera_mappings(&[mapping("LOC_1", "", CAMERA_A)])
        .unwrap();
    store.upsert_payment(&payment("PAY_NEW", 0)).unwrap();
    fs::write(store.thumbnail_dir().join("new.jpg"), b"new image").unwrap();
    let jobs = store
        .claim_due_thumbnail_retries(1, BASE_TS as f64 / 1000.0)
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(
        store
            .complete_thumbnail_retry("PAY_NEW", &jobs[0].1, CAMERA_A, BASE_TS, "new.jpg", 9, 0)
            .unwrap()
    );
    store.run_thumbnail_maintenance(false, BASE_TS).unwrap();
    assert!(!store.orphan_thumbnail_cleanup_pending().unwrap());
    assert!(!store.thumbnail_dir().join("old.jpg").exists());
    assert!(store.thumbnail_dir().join("new.jpg").exists());
    assert_eq!(
        store
            .get_transaction("PAY_NEW")
            .unwrap()
            .unwrap()
            .thumbnail_path
            .as_deref(),
        Some("new.jpg")
    );
}

#[test]
fn square_reconnect_preserves_account_data_and_webhook_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    store
        .replace_camera_mappings(&[mapping("LOC_1", "", CAMERA_A)])
        .unwrap();
    store.upsert_payment(&payment("PAY_OLD", 0)).unwrap();
    store
        .set_setting("square.webhook_signature_key", "test-old-key", true)
        .unwrap();
    store.store_oauth_state("test-state").unwrap();
    let _guard = store.integration_guard(true).unwrap();
    assert!(
        !store
            .save_square_account_under_guard(
                &[("square.access_token", "test-new-access", true)],
                &[],
                false,
            )
            .unwrap()
    );
    assert!(store.get_transaction("PAY_OLD").unwrap().is_some());
    assert_eq!(store.get_camera_mappings().unwrap().len(), 1);
    assert_eq!(
        store.get_setting("square.access_token").unwrap().as_deref(),
        Some("test-new-access")
    );
    assert_eq!(
        store
            .get_setting("square.webhook_signature_key")
            .unwrap()
            .as_deref(),
        Some("test-old-key")
    );
    assert!(!store.consume_oauth_state("test-state").unwrap());
}

#[test]
fn startup_removes_interrupted_thumbnail_writes_and_hardens_existing_files() {
    let temp = tempfile::tempdir().unwrap();
    let thumbnails = temp.path().join("thumbnails");
    fs::create_dir(&thumbnails).unwrap();
    let interrupted = thumbnails.join(".capture.uuid.tmp");
    let published = thumbnails.join("published.jpg");
    fs::write(&interrupted, b"partial").unwrap();
    fs::write(&published, b"complete").unwrap();
    let store = Store::open(temp.path()).unwrap();
    assert!(!interrupted.exists());
    assert!(published.exists());
    assert_eq!(store.thumbnail_dir(), thumbnails.as_path());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(published).unwrap().permissions().mode() & 0o077,
            0
        );
    }
}
