// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! URL generation for SAS tokens.

use crate::sas::builder::{SasResource, UserDelegationSasBuilder};
use crate::sas::signature::{format_iso8601, generate_signature, SAS_VERSION};
use azure_core::http::{Url, UrlExt};

/// Builds a SAS URL by appending SAS query parameters to the base URL.
///
/// This function:
/// 1. Generates the signature
/// 2. Clones the base URL
/// 3. Adds all SAS query parameters
/// 4. Returns the complete SAS URL
pub(crate) fn build_sas_url(
    base_url: &Url,
    resource_type: SasResource,
    builder: &UserDelegationSasBuilder,
) -> azure_core::Result<Url> {
    // Generate the signature
    let signature = generate_signature(base_url, resource_type, builder.user_delegation_key, builder)?;

    // Pre-compute string values that need to be borrowed
    let permissions_str = builder.permissions.to_string();
    let start_str = if let Some(start) = builder.start {
        Some(format_iso8601(&start)?)
    } else {
        None
    };
    let expiry_str = format_iso8601(&builder.expiry)?;
    let resource_str = resource_type.to_string();
    let ip_range_str = builder.ip_range.as_ref().map(|ip| ip.to_string());
    let protocol_str = builder.protocol.map(|p| p.to_string());

    // Clone the URL and build query parameters
    let mut url = base_url.clone();

    {
        let mut query_builder = url.query_builder();

        // signedVersion (sv)
        query_builder.set_pair("sv", SAS_VERSION);

        // signedPermissions (sp)
        query_builder.set_pair("sp", &permissions_str);

        // signedStart (st) - optional
        if let Some(ref st) = start_str {
            query_builder.set_pair("st", st);
        }

        // signedExpiry (se)
        query_builder.set_pair("se", &expiry_str);

        // signedResource (sr)
        query_builder.set_pair("sr", resource_str);

        // User delegation key parameters
        // signedKeyObjectId (skoid)
        if let Some(ref oid) = builder.user_delegation_key.signed_oid {
            query_builder.set_pair("skoid", oid);
        }

        // signedKeyTenantId (sktid)
        if let Some(ref tid) = builder.user_delegation_key.signed_tid {
            query_builder.set_pair("sktid", tid);
        }

        // signedKeyStart (skt)
        if let Some(ref start) = builder.user_delegation_key.signed_start {
            query_builder.set_pair("skt", start);
        }

        // signedKeyExpiry (ske)
        if let Some(ref expiry) = builder.user_delegation_key.signed_expiry {
            query_builder.set_pair("ske", expiry);
        }

        // signedKeyService (sks)
        if let Some(ref service) = builder.user_delegation_key.signed_service {
            query_builder.set_pair("sks", service);
        }

        // signedKeyVersion (skv)
        if let Some(ref version) = builder.user_delegation_key.signed_version {
            query_builder.set_pair("skv", version);
        }

        // Optional parameters
        // signedIp (sip)
        if let Some(ref ip_str) = ip_range_str {
            query_builder.set_pair("sip", ip_str);
        }

        // signedProtocol (spr)
        if let Some(proto_str) = protocol_str {
            query_builder.set_pair("spr", proto_str);
        }

        // signedAuthorizedUserObjectId (saoid)
        if let Some(oid) = builder.authorized_object_id {
            query_builder.set_pair("saoid", oid);
        }

        // signedCorrelationId (scid)
        if let Some(cid) = builder.correlation_id {
            query_builder.set_pair("scid", cid);
        }

        // signedEncryptionScope (ses)
        if let Some(scope) = builder.encryption_scope {
            query_builder.set_pair("ses", scope);
        }

        // Response header overrides
        // responseCacheControl (rscc)
        if let Some(cc) = builder.cache_control {
            query_builder.set_pair("rscc", cc);
        }

        // responseContentDisposition (rscd)
        if let Some(cd) = builder.content_disposition {
            query_builder.set_pair("rscd", cd);
        }

        // responseContentEncoding (rsce)
        if let Some(ce) = builder.content_encoding {
            query_builder.set_pair("rsce", ce);
        }

        // responseContentLanguage (rscl)
        if let Some(cl) = builder.content_language {
            query_builder.set_pair("rscl", cl);
        }

        // responseContentType (rsct)
        if let Some(ct) = builder.content_type {
            query_builder.set_pair("rsct", ct);
        }

        // signature (sig) - must be last
        query_builder.set_pair("sig", &signature);

        query_builder.build();
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::models::UserDelegationKey;
    use crate::sas::builder::{SasPermissions, SasProtocol, UserDelegationSasBuilder};
    use azure_core::time::OffsetDateTime;

    #[test]
    fn test_build_sas_url() {
        // Create a mock UserDelegationKey with a valid base64 key
        let key = UserDelegationKey {
            signed_oid: Some("object-id".to_string()),
            signed_tid: Some("tenant-id".to_string()),
            signed_start: Some("2021-01-01T00:00:00Z".to_string()),
            signed_expiry: Some("2021-01-02T00:00:00Z".to_string()),
            signed_service: Some("b".to_string()),
            signed_version: Some("2025-11-05".to_string()),
            value: Some(vec![1, 2, 3, 4, 5, 6, 7, 8]), // Mock key
        };

        let expiry = OffsetDateTime::from_unix_timestamp(1609545600).unwrap();
        let builder = UserDelegationSasBuilder::new(&key, SasPermissions::read(), expiry);

        let base_url = Url::parse("https://myaccount.blob.core.windows.net/container/blob").unwrap();
        let sas_url = build_sas_url(&base_url, SasResource::Blob, &builder).unwrap();

        let query = sas_url.query().unwrap();

        // Verify required parameters are present
        assert!(query.contains("sv="));
        assert!(query.contains("sp=r"));
        assert!(query.contains("se="));
        assert!(query.contains("sr=b"));
        assert!(query.contains("skoid=object-id"));
        assert!(query.contains("sktid=tenant-id"));
        assert!(query.contains("skt=2021-01-01T00:00:00Z"));
        assert!(query.contains("ske=2021-01-02T00:00:00Z"));
        assert!(query.contains("sks=b"));
        assert!(query.contains("skv=2025-11-05"));
        assert!(query.contains("sig="));

        // Verify base URL is preserved
        assert_eq!(sas_url.host_str().unwrap(), "myaccount.blob.core.windows.net");
        assert_eq!(sas_url.path(), "/container/blob");
    }

    #[test]
    fn test_build_sas_url_with_optional_params() {
        let key = UserDelegationKey {
            signed_oid: Some("object-id".to_string()),
            signed_tid: Some("tenant-id".to_string()),
            signed_start: Some("2021-01-01T00:00:00Z".to_string()),
            signed_expiry: Some("2021-01-02T00:00:00Z".to_string()),
            signed_service: Some("b".to_string()),
            signed_version: Some("2025-11-05".to_string()),
            value: Some(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        };

        let expiry = OffsetDateTime::from_unix_timestamp(1609545600).unwrap();
        let builder = UserDelegationSasBuilder::new(&key, SasPermissions::read(), expiry)
            .with_protocol(SasProtocol::Https)
            .with_content_disposition("attachment; filename=\"file.txt\"");

        let base_url = Url::parse("https://myaccount.blob.core.windows.net/container/blob").unwrap();
        let sas_url = build_sas_url(&base_url, SasResource::Blob, &builder).unwrap();

        let query = sas_url.query().unwrap();

        // Verify optional parameters
        assert!(query.contains("spr=https"));
        assert!(query.contains("rscd=attachment"));
    }
}
