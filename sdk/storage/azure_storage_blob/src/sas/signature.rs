// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Signature generation for User Delegation SAS tokens.

use crate::generated::models::UserDelegationKey;
use crate::sas::builder::{SasResource, UserDelegationSasBuilder};
use azure_core::{
    credentials::Secret,
    error::{ErrorKind, ResultExt},
    hmac, time::OffsetDateTime,
};

/// The API version to use for SAS tokens.
pub(crate) const SAS_VERSION: &str = "2025-11-05";

/// Formats an OffsetDateTime in ISO 8601 / RFC 3339 format for Azure Storage.
///
/// Format: YYYY-MM-DDTHH:MM:SSZ (UTC timezone)
pub(crate) fn format_iso8601(dt: &OffsetDateTime) -> azure_core::Result<String> {
    dt.format(&time::format_description::well_known::Rfc3339)
        .with_context_fn(ErrorKind::DataConversion, || {
            "failed to format datetime as ISO 8601"
        })
}

/// Extracts the storage account name from a blob storage URL.
///
/// Example: https://myaccount.blob.core.windows.net/container/blob -> "myaccount"
pub(crate) fn extract_account_name(
    url: &azure_core::http::Url,
) -> azure_core::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| {
            azure_core::Error::with_message(ErrorKind::DataConversion, "URL has no host")
        })?;

    let account_name = host
        .split('.')
        .next()
        .ok_or_else(|| {
            azure_core::Error::with_message(ErrorKind::DataConversion, "invalid host format in URL")
        })?;

    Ok(account_name.to_string())
}

/// Builds the canonicalized resource path for the SAS token.
///
/// Format: /blob/{account_name}/{container_name}/{blob_name}
/// or: /blob/{account_name}/{container_name}
pub(crate) fn build_canonicalized_resource(
    account_name: &str,
    resource_path: &str,
) -> String {
    format!("/blob/{}{}", account_name, resource_path)
}

/// Constructs the string-to-sign for a User Delegation SAS token.
///
/// This follows the Azure Storage specification for version 2020-12-06 and later.
///
/// The string-to-sign format is:
/// ```text
/// signedPermissions + "\n" +
/// signedStart + "\n" +
/// signedExpiry + "\n" +
/// canonicalizedResource + "\n" +
/// signedKeyObjectId + "\n" +
/// signedKeyTenantId + "\n" +
/// signedKeyStart + "\n" +
/// signedKeyExpiry + "\n" +
/// signedKeyService + "\n" +
/// signedKeyVersion + "\n" +
/// signedAuthorizedUserObjectId + "\n" +
/// signedUnauthorizedUserObjectId + "\n" +
/// signedCorrelationId + "\n" +
/// signedIP + "\n" +
/// signedProtocol + "\n" +
/// signedVersion + "\n" +
/// signedResource + "\n" +
/// signedSnapshotTime + "\n" +
/// signedEncryptionScope + "\n" +
/// rscc + "\n" +
/// rscd + "\n" +
/// rsce + "\n" +
/// rscl + "\n" +
/// rsct
/// ```
pub(crate) fn build_string_to_sign(
    canonicalized_resource: &str,
    resource_type: SasResource,
    user_delegation_key: &UserDelegationKey,
    builder: &UserDelegationSasBuilder,
) -> azure_core::Result<String> {
    // Pre-allocate with approximate capacity
    let mut string_to_sign = String::with_capacity(512);

    // signedPermissions
    string_to_sign.push_str(&builder.permissions.to_string());
    string_to_sign.push('\n');

    // signedStart
    if let Some(start) = builder.start {
        string_to_sign.push_str(&format_iso8601(&start)?);
    }
    string_to_sign.push('\n');

    // signedExpiry
    string_to_sign.push_str(&format_iso8601(&builder.expiry)?);
    string_to_sign.push('\n');

    // canonicalizedResource
    string_to_sign.push_str(canonicalized_resource);
    string_to_sign.push('\n');

    // signedKeyObjectId
    if let Some(ref oid) = user_delegation_key.signed_oid {
        string_to_sign.push_str(oid);
    }
    string_to_sign.push('\n');

    // signedKeyTenantId
    if let Some(ref tid) = user_delegation_key.signed_tid {
        string_to_sign.push_str(tid);
    }
    string_to_sign.push('\n');

    // signedKeyStart
    if let Some(ref start) = user_delegation_key.signed_start {
        string_to_sign.push_str(start);
    }
    string_to_sign.push('\n');

    // signedKeyExpiry
    if let Some(ref expiry) = user_delegation_key.signed_expiry {
        string_to_sign.push_str(expiry);
    }
    string_to_sign.push('\n');

    // signedKeyService
    if let Some(ref service) = user_delegation_key.signed_service {
        string_to_sign.push_str(service);
    }
    string_to_sign.push('\n');

    // signedKeyVersion
    if let Some(ref version) = user_delegation_key.signed_version {
        string_to_sign.push_str(version);
    }
    string_to_sign.push('\n');

    // signedAuthorizedUserObjectId
    if let Some(ref oid) = builder.authorized_object_id {
        string_to_sign.push_str(oid);
    }
    string_to_sign.push('\n');

    // signedUnauthorizedUserObjectId (not currently supported)
    string_to_sign.push('\n');

    // signedCorrelationId
    if let Some(ref cid) = builder.correlation_id {
        string_to_sign.push_str(cid);
    }
    string_to_sign.push('\n');

    // signedIP
    if let Some(ref ip_range) = builder.ip_range {
        string_to_sign.push_str(&ip_range.to_string());
    }
    string_to_sign.push('\n');

    // signedProtocol
    if let Some(protocol) = builder.protocol {
        string_to_sign.push_str(protocol.to_string());
    }
    string_to_sign.push('\n');

    // signedVersion
    string_to_sign.push_str(SAS_VERSION);
    string_to_sign.push('\n');

    // signedResource
    string_to_sign.push_str(resource_type.to_string());
    string_to_sign.push('\n');

    // signedSnapshotTime (not currently supported)
    string_to_sign.push('\n');

    // signedEncryptionScope
    if let Some(ref scope) = builder.encryption_scope {
        string_to_sign.push_str(scope);
    }
    string_to_sign.push('\n');

    // Response header overrides
    // rscc (Cache-Control)
    if let Some(ref cc) = builder.cache_control {
        string_to_sign.push_str(cc);
    }
    string_to_sign.push('\n');

    // rscd (Content-Disposition)
    if let Some(ref cd) = builder.content_disposition {
        string_to_sign.push_str(cd);
    }
    string_to_sign.push('\n');

    // rsce (Content-Encoding)
    if let Some(ref ce) = builder.content_encoding {
        string_to_sign.push_str(ce);
    }
    string_to_sign.push('\n');

    // rscl (Content-Language)
    if let Some(ref cl) = builder.content_language {
        string_to_sign.push_str(cl);
    }
    string_to_sign.push('\n');

    // rsct (Content-Type)
    if let Some(ref ct) = builder.content_type {
        string_to_sign.push_str(ct);
    }

    Ok(string_to_sign)
}

/// Signs the string-to-sign using the user delegation key to produce a SAS signature.
///
/// Uses HMAC-SHA256 with the user delegation key's value as the key.
/// Returns a base64-encoded signature.
pub(crate) fn sign_string(
    string_to_sign: &str,
    user_delegation_key: &UserDelegationKey,
) -> azure_core::Result<String> {
    // Get the user delegation key value
    let key_value = user_delegation_key
        .value
        .as_ref()
        .ok_or_else(|| {
            azure_core::Error::with_message(
                ErrorKind::DataConversion,
                "user delegation key has no value",
            )
        })?;

    // Convert the key to a base64 string (it's stored as Vec<u8>)
    let key_base64 = azure_core::base64::encode(key_value);
    let secret = Secret::new(key_base64);

    // Sign the string using HMAC-SHA256
    hmac::hmac_sha256(string_to_sign, &secret)
}

/// Generates a complete SAS signature for a User Delegation SAS token.
///
/// This is the main entry point for signature generation.
pub(crate) fn generate_signature(
    url: &azure_core::http::Url,
    resource_type: SasResource,
    user_delegation_key: &UserDelegationKey,
    builder: &UserDelegationSasBuilder,
) -> azure_core::Result<String> {
    // Extract account name from URL
    let account_name = extract_account_name(url)?;

    // Get resource path (e.g., "/container/blob")
    let resource_path = url.path();

    // Build canonicalized resource
    let canonicalized_resource = build_canonicalized_resource(&account_name, resource_path);

    // Build string to sign
    let string_to_sign =
        build_string_to_sign(&canonicalized_resource, resource_type, user_delegation_key, builder)?;

    // Sign the string
    sign_string(&string_to_sign, user_delegation_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::http::Url;

    #[test]
    fn test_extract_account_name() {
        let url = Url::parse("https://myaccount.blob.core.windows.net/container/blob").unwrap();
        assert_eq!(extract_account_name(&url).unwrap(), "myaccount");

        let url = Url::parse("https://storageacct.blob.core.windows.net/").unwrap();
        assert_eq!(extract_account_name(&url).unwrap(), "storageacct");
    }

    #[test]
    fn test_build_canonicalized_resource() {
        let result = build_canonicalized_resource("myaccount", "/container/blob");
        assert_eq!(result, "/blob/myaccount/container/blob");

        let result = build_canonicalized_resource("myaccount", "/container");
        assert_eq!(result, "/blob/myaccount/container");
    }

    #[test]
    fn test_format_iso8601() {
        // Test with a known date
        let dt = OffsetDateTime::from_unix_timestamp(1609459200).unwrap(); // 2021-01-01 00:00:00 UTC
        let formatted = format_iso8601(&dt).unwrap();
        assert!(formatted.starts_with("2021-01-01"));
        assert!(formatted.ends_with('Z'));
    }

    #[test]
    fn test_build_string_to_sign() {
        use crate::sas::builder::SasPermissions;

        // Create a mock UserDelegationKey
        let key = UserDelegationKey {
            signed_oid: Some("object-id".to_string()),
            signed_tid: Some("tenant-id".to_string()),
            signed_start: Some("2021-01-01T00:00:00Z".to_string()),
            signed_expiry: Some("2021-01-02T00:00:00Z".to_string()),
            signed_service: Some("b".to_string()),
            signed_version: Some("2025-11-05".to_string()),
            value: Some(vec![1, 2, 3, 4]),
        };

        let expiry = OffsetDateTime::from_unix_timestamp(1609545600).unwrap(); // 2021-01-02 00:00:00 UTC
        let builder = UserDelegationSasBuilder::new(
            &key,
            SasPermissions::read(),
            expiry,
        );

        let string_to_sign = build_string_to_sign(
            "/blob/myaccount/container/blob",
            SasResource::Blob,
            &key,
            &builder,
        )
        .unwrap();

        // Verify the string contains key components
        assert!(string_to_sign.contains("r\n")); // permissions
        assert!(string_to_sign.contains("/blob/myaccount/container/blob\n")); // canonicalized resource
        assert!(string_to_sign.contains("object-id\n")); // signed oid
        assert!(string_to_sign.contains("tenant-id\n")); // signed tid
        assert!(string_to_sign.contains(SAS_VERSION)); // version
        assert!(string_to_sign.contains("b\n")); // resource type (after many newlines)
    }
}
