// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! User Delegation SAS URL generation for Azure Blob Storage.
//!
//! This module provides functionality to generate time-limited, cryptographically-signed
//! URLs for accessing Azure Blob Storage resources using Entra ID authentication.
//!
//! # Overview
//!
//! Shared Access Signatures (SAS) provide a way to grant limited access to your Azure Storage
//! resources without sharing your account keys. User Delegation SAS tokens are particularly
//! secure because they're signed with Entra ID credentials instead of storage account keys.
//!
//! # Example
//!
//! ```no_run
//! use azure_storage_blob::{BlobServiceClient, sas::SasPermissions};
//! use azure_identity::DefaultAzureCredential;
//! use azure_core::time::OffsetDateTime;
//! use std::{sync::Arc, time::Duration};
//!
//! # async fn example() -> azure_core::Result<()> {
//! // Create service client with Entra ID authentication
//! let credential = Arc::new(DefaultAzureCredential::new()?);
//! let service_client = BlobServiceClient::new(
//!     "https://myaccount.blob.core.windows.net",
//!     Some(credential),
//!     None,
//! )?;
//!
//! // Get a user delegation key (valid for 1 hour)
//! let key_start = OffsetDateTime::now_utc();
//! let key_expiry = key_start + Duration::from_secs(3600);
//! let key = service_client
//!     .get_user_delegation_key(key_start, key_expiry, None)
//!     .await?
//!     .into_model()?;
//!
//! // Generate SAS URL for a blob (valid for 1 hour)
//! let blob_client = service_client
//!     .blob_container_client("mycontainer")
//!     .blob_client("myblob.txt");
//!
//! let sas_url = blob_client.generate_sas_url(
//!     &key,
//!     SasPermissions::read(),
//!     OffsetDateTime::now_utc() + Duration::from_secs(3600),
//! )?;
//!
//! println!("SAS URL: {}", sas_url);
//!
//! // Use the SAS URL without credentials
//! let sas_blob_client = azure_storage_blob::BlobClient::from_url(
//!     sas_url,
//!     None, // No credential needed!
//!     None,
//! )?;
//!
//! let response = sas_blob_client.download(None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Advanced Usage
//!
//! For more control over the SAS parameters, use the builder pattern:
//!
//! ```no_run
//! use azure_storage_blob::sas::{SasPermissions, SasProtocol, SasIpRange};
//! use std::net::IpAddr;
//! # use azure_core::time::OffsetDateTime;
//! # use std::time::Duration;
//!
//! # async fn example() -> azure_core::Result<()> {
//! # let blob_client: azure_storage_blob::BlobClient = todo!();
//! # let key = todo!();
//! # let expiry = OffsetDateTime::now_utc() + Duration::from_secs(3600);
//! // Generate SAS with custom options
//! let sas_url = blob_client
//!     .sas_builder(&key, SasPermissions::read(), expiry)
//!     .with_protocol(SasProtocol::Https)
//!     .with_ip_range(SasIpRange::new(
//!         "203.0.113.0".parse()?,
//!         Some("203.0.113.255".parse()?),
//!     ))
//!     .with_content_disposition("attachment; filename=\"data.txt\"")
//!     .build_blob_url(blob_client.url())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - **Use HTTPS**: Always use `SasProtocol::Https` in production to prevent token interception
//! - **Limit permissions**: Only grant the minimum permissions needed (read-only when possible)
//! - **Short expiry**: Use short expiry times (e.g., 1 hour) and regenerate as needed
//! - **IP restrictions**: Consider using `SasIpRange` to limit access to known IP addresses
//! - **User delegation keys**: Valid for up to 7 days, but shorter periods are recommended

mod builder;
mod signature;
mod url;

pub use builder::{
    SasIpRange, SasPermissions, SasProtocol, UserDelegationSasBuilder,
};
