use smart_vpn_engine::network_helper::Request;
#[test]
fn rejects_arbitrary_paths_commands_and_unknown_operations() {
    for raw in [
        r#"{"operation":"shell","data":"id"}"#,
        r#"{"operation":"status","path":"/etc/passwd"}"#,
        r#"{"operation":"start","data":{"binary":"/bin/sh","config":{}}}"#,
    ] {
        assert!(serde_json::from_str::<Request>(raw).is_err(), "{raw}");
    }
}
#[test]
fn stop_and_recovery_have_no_caller_supplied_system_arguments() {
    assert!(serde_json::from_str::<Request>(r#"{"operation":"stop"}"#).is_ok());
    assert!(serde_json::from_str::<Request>(r#"{"operation":"test_recovery"}"#).is_ok());
    assert!(
        serde_json::from_str::<Request>(r#"{"operation":"stop","data":{"path":"/"}}"#).is_err()
    );
}
