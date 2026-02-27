//! OpenWrt UBus lightweight IPC interface for dnsmasq.
//!
//! Provides metrics export, DHCP lease event broadcasting, and connmark
//! allowlist management for OpenWrt deployments. Replaces the C implementation
//! in `src/ubus.c` (968 lines).
//!
//! This is a stub awaiting full implementation by the code generation agent.

/// UBus integration state.
///
/// Encapsulates the UBus connection context, service identity, and runtime flags.
/// Replaces C's static `ubus_context` pointer and `error_logged` / subscriber tracking.
pub struct UbusState {
    /// Opaque pointer to the libubus context (NULL when disconnected).
    pub context: Option<UbusContext>,
    /// The UBus object name registered for this instance (default: "dnsmasq").
    pub service_name: String,
    /// Flag to suppress duplicate error log messages on repeated failures.
    pub error_logged: bool,
    /// Whether any UBus clients have subscribed for event notifications.
    pub has_subscribers: bool,
}

/// Opaque wrapper around the libubus context.
///
/// Will be replaced with a proper FFI pointer by the full implementation agent.
pub struct UbusContext;

/// Errors that can occur during UBus operations.
#[derive(Debug)]
pub enum UbusError {
    /// Failed to connect to ubusd.
    ConnectionFailed,
    /// Failed to register the UBus object.
    RegistrationFailed(String),
    /// UBus context is not available (disconnected).
    NoContext,
}

impl std::fmt::Display for UbusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UbusError::ConnectionFailed => write!(f, "Failed to connect to ubusd"),
            UbusError::RegistrationFailed(msg) => {
                write!(f, "Failed to register UBus object: {msg}")
            }
            UbusError::NoContext => write!(f, "UBus context unavailable"),
        }
    }
}

impl std::error::Error for UbusError {}

impl UbusState {
    /// Create a new `UbusState` with default values.
    ///
    /// Does not establish a connection — call [`ubus_init`] for that.
    pub fn new() -> Self {
        Self {
            context: None,
            service_name: "dnsmasq".to_string(),
            error_logged: false,
            has_subscribers: false,
        }
    }
}

impl Default for UbusState {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize the UBus connection and register the dnsmasq object.
///
/// Returns `Ok(Some(state))` on success, `Ok(None)` if ubusd is unavailable
/// (non-fatal), or `Err` on registration failure.
pub fn ubus_init() -> Result<Option<UbusState>, UbusError> {
    // Full implementation will be provided by the UBus code generation agent.
    Ok(Some(UbusState::new()))
}

/// Register UBus socket file descriptor with the poll event loop.
pub fn set_ubus_listeners(_state: &UbusState) {
    // Full implementation will be provided by the UBus code generation agent.
}

/// Dispatch UBus events after poll indicates readiness.
pub fn check_ubus_listeners(_state: &mut UbusState) {
    // Full implementation will be provided by the UBus code generation agent.
}

/// Broadcast a DHCP lease event to UBus subscribers.
///
/// No-op when no subscribers are registered (optimization matching C behavior).
pub fn ubus_event(_state: &UbusState, _event_type: &str, _mac: &str, _ip: &str, _name: &str, _interface: &str) {
    // Full implementation will be provided by the UBus code generation agent.
}
