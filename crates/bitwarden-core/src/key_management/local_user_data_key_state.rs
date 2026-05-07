use tracing::info;

use crate::{
    Client, UserId,
    key_management::{self, SymmetricKeySlotId, local_user_data_key::WrappedLocalUserDataKey},
};

pub(crate) struct InitLocalUserDataKeyError;

/// Stores [`WrappedLocalUserDataKey`] in state if one does not already exist.
pub(crate) async fn initialize_local_user_data_key_into_state(
    client: &Client,
    user_id: UserId,
) -> Result<(), InitLocalUserDataKeyError> {
    let repo = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| InitLocalUserDataKeyError)?;

    // Idempotent: only set if no key is present yet.
    if let Ok(Some(_)) = repo.get(user_id).await {
        info!("WrappedLocalUserDataKey already exists in state, skipping");
        return Ok(());
    }

    info!("Setting WrappedLocalUserDataKey to state from user key");
    let wrapped_local_user_data_key = {
        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();
        WrappedLocalUserDataKey::from_context_user_key(&mut ctx)
            .map_err(|_| InitLocalUserDataKeyError)?
    };

    repo.set(user_id, wrapped_local_user_data_key.into())
        .await
        .map_err(|_| InitLocalUserDataKeyError)
}

pub(crate) struct MigrateLocalUserDataKeyForUserKeyUpgradeError;

/// Re-wraps a persisted [`WrappedLocalUserDataKey`] with the current user key after a V1→V2
/// user-key upgrade. Preserves the inner-key plaintext so local data encrypted before the
/// upgrade remains decryptable.
///
/// No-op when:
/// - state bridge is not registered by the host
/// - upgrade token is not available
/// - no `LocalUserDataKeyState` is present for `user_id` yet (first-time init handles creation),
pub(crate) async fn migrate_local_user_data_key_for_user_key_upgrade(
    client: &Client,
    user_id: UserId,
) -> Result<(), MigrateLocalUserDataKeyForUserKeyUpgradeError> {
    // Todo: Remove when all host clients implement the state bridge
    if !client.internal.state_bridge.is_registered() {
        info!("No state bridge registered, skipping WrappedLocalUserDataKey migration");
        return Ok(());
    }

    let Some(token) = client.internal.state_bridge.get_v2_upgrade_token().await else {
        info!(
            "No V2 upgrade token available from state bridge, skipping WrappedLocalUserDataKey migration"
        );
        return Ok(());
    };

    let repo = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| MigrateLocalUserDataKeyForUserKeyUpgradeError)?;
    let Some(state) = repo
        .get(user_id)
        .await
        .map_err(|_| MigrateLocalUserDataKeyForUserKeyUpgradeError)?
    else {
        return Ok(());
    };

    let rewrapped = {
        let mut ctx = client.internal.get_key_store().context_mut();
        let Ok(v1_user_key_id) =  token.unwrap_v1(SymmetricKeySlotId::User, &mut ctx) else {
            info!(
                "Upgrade token does not apply to current user key, skipping WrappedLocalUserDataKey migration"
            );
            return Ok(());
        };

        let wrapped = WrappedLocalUserDataKey(state.wrapped_key);
        wrapped
            .rewrap_with_user_key(v1_user_key_id, &mut ctx)
            .map_err(|_| MigrateLocalUserDataKeyForUserKeyUpgradeError)?
    };

    info!("Rewrapping WrappedLocalUserDataKey with current user key");
    repo.set(user_id, rewrapped.into())
        .await
        .map_err(|_| MigrateLocalUserDataKeyForUserKeyUpgradeError)
}

pub(crate) struct UnableToGetError;

/// Retrieves the [`WrappedLocalUserDataKey`] from state.
pub(crate) async fn get_local_user_data_key_from_state(
    client: &Client,
    user_id: UserId,
) -> Result<WrappedLocalUserDataKey, UnableToGetError> {
    info!("Getting the WrappedLocalUserDataKey from state");
    let user_local_data_key_state = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| UnableToGetError)?
        .get(user_id)
        .await
        .map_err(|_| UnableToGetError)?
        .ok_or(UnableToGetError)?;

    Ok(WrappedLocalUserDataKey(
        user_local_data_key_state.wrapped_key,
    ))
}
