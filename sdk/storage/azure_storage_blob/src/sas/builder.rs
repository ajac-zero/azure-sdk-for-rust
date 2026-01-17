// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Builder for creating User Delegation SAS tokens.

use crate::generated::models::UserDelegationKey;
use azure_core::time::OffsetDateTime;
use std::net::IpAddr;

/// Represents the permissions for a Shared Access Signature (SAS).
///
/// # Example
///
/// ```
/// use azure_storage_blob::sas::SasPermissions;
///
/// // Create read-only permissions
/// let perms = SasPermissions::read();
///
/// // Create read-write permissions
/// let perms = SasPermissions::read_write();
///
/// // Create custom permissions
/// let perms = SasPermissions::new()
///     .with_read()
///     .with_write()
///     .with_delete()
///     .with_list();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasPermissions {
    read: bool,
    add: bool,
    create: bool,
    write: bool,
    delete: bool,
    delete_version: bool,
    permanent_delete: bool,
    list: bool,
    tags: bool,
    filter_by_tags: bool,
    move_: bool,
    execute: bool,
    ownership: bool,
    permissions: bool,
}

impl SasPermissions {
    /// Creates a new `SasPermissions` with all permissions set to false.
    pub fn new() -> Self {
        Self {
            read: false,
            add: false,
            create: false,
            write: false,
            delete: false,
            delete_version: false,
            permanent_delete: false,
            list: false,
            tags: false,
            filter_by_tags: false,
            move_: false,
            execute: false,
            ownership: false,
            permissions: false,
        }
    }

    /// Creates permissions with read access only.
    pub fn read() -> Self {
        Self::new().with_read()
    }

    /// Creates permissions with read and write access.
    pub fn read_write() -> Self {
        Self::new().with_read().with_write()
    }

    /// Creates permissions with read, write, and delete access.
    pub fn read_write_delete() -> Self {
        Self::new().with_read().with_write().with_delete()
    }

    /// Adds read permission.
    pub fn with_read(mut self) -> Self {
        self.read = true;
        self
    }

    /// Adds add permission.
    pub fn with_add(mut self) -> Self {
        self.add = true;
        self
    }

    /// Adds create permission.
    pub fn with_create(mut self) -> Self {
        self.create = true;
        self
    }

    /// Adds write permission.
    pub fn with_write(mut self) -> Self {
        self.write = true;
        self
    }

    /// Adds delete permission.
    pub fn with_delete(mut self) -> Self {
        self.delete = true;
        self
    }

    /// Adds delete version permission.
    pub fn with_delete_version(mut self) -> Self {
        self.delete_version = true;
        self
    }

    /// Adds permanent delete permission.
    pub fn with_permanent_delete(mut self) -> Self {
        self.permanent_delete = true;
        self
    }

    /// Adds list permission.
    pub fn with_list(mut self) -> Self {
        self.list = true;
        self
    }

    /// Adds tags permission.
    pub fn with_tags(mut self) -> Self {
        self.tags = true;
        self
    }

    /// Adds filter by tags permission.
    pub fn with_filter_by_tags(mut self) -> Self {
        self.filter_by_tags = true;
        self
    }

    /// Adds move permission.
    pub fn with_move(mut self) -> Self {
        self.move_ = true;
        self
    }

    /// Adds execute permission.
    pub fn with_execute(mut self) -> Self {
        self.execute = true;
        self
    }

    /// Adds ownership permission.
    pub fn with_ownership(mut self) -> Self {
        self.ownership = true;
        self
    }

    /// Adds permissions permission.
    pub fn with_permissions(mut self) -> Self {
        self.permissions = true;
        self
    }

    /// Converts the permissions to the Azure Storage SAS permissions string format.
    ///
    /// The permissions are always returned in the canonical order: racwdxytlmeopi
    pub(crate) fn to_string(&self) -> String {
        let mut result = String::with_capacity(14);
        if self.read {
            result.push('r');
        }
        if self.add {
            result.push('a');
        }
        if self.create {
            result.push('c');
        }
        if self.write {
            result.push('w');
        }
        if self.delete {
            result.push('d');
        }
        if self.delete_version {
            result.push('x');
        }
        if self.permanent_delete {
            result.push('y');
        }
        if self.tags {
            result.push('t');
        }
        if self.list {
            result.push('l');
        }
        if self.move_ {
            result.push('m');
        }
        if self.execute {
            result.push('e');
        }
        if self.ownership {
            result.push('o');
        }
        if self.permissions {
            result.push('p');
        }
        if self.filter_by_tags {
            result.push('i');
        }
        result
    }
}

impl Default for SasPermissions {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an IP address range for SAS token restrictions.
///
/// # Example
///
/// ```
/// use azure_storage_blob::sas::SasIpRange;
/// use std::net::IpAddr;
///
/// // Single IP address
/// let ip_range = SasIpRange::new("203.0.113.5".parse().unwrap(), None);
///
/// // IP range
/// let ip_range = SasIpRange::new(
///     "203.0.113.0".parse().unwrap(),
///     Some("203.0.113.255".parse().unwrap()),
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasIpRange {
    start: IpAddr,
    end: Option<IpAddr>,
}

impl SasIpRange {
    /// Creates a new IP range.
    ///
    /// # Arguments
    ///
    /// * `start` - The starting IP address
    /// * `end` - The ending IP address (optional). If None, only the start IP is allowed.
    pub fn new(start: IpAddr, end: Option<IpAddr>) -> Self {
        Self { start, end }
    }

    /// Converts the IP range to the Azure Storage SAS format.
    pub(crate) fn to_string(&self) -> String {
        if let Some(end) = &self.end {
            format!("{}-{}", self.start, end)
        } else {
            self.start.to_string()
        }
    }
}

/// Specifies the protocol permitted for a SAS token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasProtocol {
    /// Only HTTPS requests are permitted.
    Https,
    /// Both HTTP and HTTPS requests are permitted.
    HttpsAndHttp,
}

impl SasProtocol {
    /// Converts the protocol to the Azure Storage SAS format.
    pub(crate) fn to_string(&self) -> &'static str {
        match self {
            SasProtocol::Https => "https",
            SasProtocol::HttpsAndHttp => "https,http",
        }
    }
}

/// Represents the type of resource being accessed with a SAS token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SasResource {
    /// Blob resource.
    Blob,
    /// Container resource.
    Container,
}

impl SasResource {
    /// Converts the resource type to the Azure Storage SAS format.
    pub(crate) fn to_string(&self) -> &'static str {
        match self {
            SasResource::Blob => "b",
            SasResource::Container => "c",
        }
    }
}

/// Builder for creating User Delegation SAS URLs.
///
/// This builder allows you to configure all aspects of a User Delegation SAS token
/// and generate a signed URL that can be used to access Azure Blob Storage resources
/// without providing credentials.
///
/// # Example
///
/// ```no_run
/// use azure_storage_blob::sas::{UserDelegationSasBuilder, SasPermissions, SasProtocol};
/// use azure_core::time::OffsetDateTime;
/// use std::time::Duration;
///
/// # async fn example() -> azure_core::Result<()> {
/// # let user_delegation_key = todo!();
/// # let blob_url = todo!();
/// let expiry = OffsetDateTime::now_utc() + Duration::from_secs(3600);
///
/// let sas_url = UserDelegationSasBuilder::new(
///     &user_delegation_key,
///     SasPermissions::read(),
///     expiry,
/// )
/// .with_protocol(SasProtocol::Https)
/// .with_content_disposition("attachment; filename=\"file.txt\"")
/// .build_blob_url(&blob_url)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct UserDelegationSasBuilder<'a> {
    pub(crate) user_delegation_key: &'a UserDelegationKey,
    pub(crate) permissions: SasPermissions,
    pub(crate) expiry: OffsetDateTime,
    pub(crate) start: Option<OffsetDateTime>,
    pub(crate) ip_range: Option<SasIpRange>,
    pub(crate) protocol: Option<SasProtocol>,
    pub(crate) cache_control: Option<&'a str>,
    pub(crate) content_disposition: Option<&'a str>,
    pub(crate) content_encoding: Option<&'a str>,
    pub(crate) content_language: Option<&'a str>,
    pub(crate) content_type: Option<&'a str>,
    pub(crate) authorized_object_id: Option<&'a str>,
    pub(crate) correlation_id: Option<&'a str>,
    pub(crate) encryption_scope: Option<&'a str>,
}

impl<'a> UserDelegationSasBuilder<'a> {
    /// Creates a new `UserDelegationSasBuilder`.
    ///
    /// # Arguments
    ///
    /// * `user_delegation_key` - The user delegation key obtained from `BlobServiceClient::get_user_delegation_key()`
    /// * `permissions` - The permissions to grant
    /// * `expiry` - When the SAS token expires
    pub fn new(
        user_delegation_key: &'a UserDelegationKey,
        permissions: SasPermissions,
        expiry: OffsetDateTime,
    ) -> Self {
        Self {
            user_delegation_key,
            permissions,
            expiry,
            start: None,
            ip_range: None,
            protocol: None,
            cache_control: None,
            content_disposition: None,
            content_encoding: None,
            content_language: None,
            content_type: None,
            authorized_object_id: None,
            correlation_id: None,
            encryption_scope: None,
        }
    }

    /// Sets the start time for the SAS token.
    ///
    /// If not set, the token is valid immediately.
    pub fn with_start(mut self, start: OffsetDateTime) -> Self {
        self.start = Some(start);
        self
    }

    /// Sets the allowed IP address range for the SAS token.
    pub fn with_ip_range(mut self, ip_range: SasIpRange) -> Self {
        self.ip_range = Some(ip_range);
        self
    }

    /// Sets the protocol(s) permitted for requests made with the SAS token.
    ///
    /// Defaults to allowing both HTTP and HTTPS if not set.
    /// For security, consider using `SasProtocol::Https`.
    pub fn with_protocol(mut self, protocol: SasProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Sets the Cache-Control header value to return when the SAS is used.
    pub fn with_cache_control(mut self, cache_control: &'a str) -> Self {
        self.cache_control = Some(cache_control);
        self
    }

    /// Sets the Content-Disposition header value to return when the SAS is used.
    ///
    /// This is useful for triggering downloads with specific filenames.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_content_disposition("attachment; filename=\"data.txt\"")
    /// ```
    pub fn with_content_disposition(mut self, content_disposition: &'a str) -> Self {
        self.content_disposition = Some(content_disposition);
        self
    }

    /// Sets the Content-Encoding header value to return when the SAS is used.
    pub fn with_content_encoding(mut self, content_encoding: &'a str) -> Self {
        self.content_encoding = Some(content_encoding);
        self
    }

    /// Sets the Content-Language header value to return when the SAS is used.
    pub fn with_content_language(mut self, content_language: &'a str) -> Self {
        self.content_language = Some(content_language);
        self
    }

    /// Sets the Content-Type header value to return when the SAS is used.
    pub fn with_content_type(mut self, content_type: &'a str) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Sets the Azure Active Directory object ID of an authorized user.
    ///
    /// The Azure Storage service will ensure that the owner of the user delegation key
    /// has the necessary permissions to grant access.
    pub fn with_authorized_object_id(mut self, oid: &'a str) -> Self {
        self.authorized_object_id = Some(oid);
        self
    }

    /// Sets a correlation ID for tracking requests made with the SAS token.
    pub fn with_correlation_id(mut self, correlation_id: &'a str) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Sets the encryption scope to use for requests made with the SAS token.
    pub fn with_encryption_scope(mut self, scope: &'a str) -> Self {
        self.encryption_scope = Some(scope);
        self
    }

    /// Builds a SAS URL for a blob.
    ///
    /// # Arguments
    ///
    /// * `blob_url` - The URL of the blob
    ///
    /// # Returns
    ///
    /// A URL with SAS query parameters appended
    pub fn build_blob_url(self, blob_url: &azure_core::http::Url) -> azure_core::Result<azure_core::http::Url> {
        crate::sas::url::build_sas_url(blob_url, SasResource::Blob, &self)
    }

    /// Builds a SAS URL for a container.
    ///
    /// # Arguments
    ///
    /// * `container_url` - The URL of the container
    ///
    /// # Returns
    ///
    /// A URL with SAS query parameters appended
    pub fn build_container_url(self, container_url: &azure_core::http::Url) -> azure_core::Result<azure_core::http::Url> {
        crate::sas::url::build_sas_url(container_url, SasResource::Container, &self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permissions_to_string() {
        assert_eq!(SasPermissions::read().to_string(), "r");
        assert_eq!(SasPermissions::read_write().to_string(), "rw");
        assert_eq!(SasPermissions::read_write_delete().to_string(), "rwd");

        let perms = SasPermissions::new()
            .with_read()
            .with_add()
            .with_create()
            .with_write()
            .with_delete()
            .with_list();
        assert_eq!(perms.to_string(), "racwdl");

        // Test all permissions in canonical order
        let all_perms = SasPermissions::new()
            .with_read()
            .with_add()
            .with_create()
            .with_write()
            .with_delete()
            .with_delete_version()
            .with_permanent_delete()
            .with_tags()
            .with_list()
            .with_move()
            .with_execute()
            .with_ownership()
            .with_permissions()
            .with_filter_by_tags();
        assert_eq!(all_perms.to_string(), "racwdxytlmeopi");
    }

    #[test]
    fn test_ip_range_to_string() {
        let single_ip = SasIpRange::new("203.0.113.5".parse().unwrap(), None);
        assert_eq!(single_ip.to_string(), "203.0.113.5");

        let ip_range = SasIpRange::new(
            "203.0.113.0".parse().unwrap(),
            Some("203.0.113.255".parse().unwrap()),
        );
        assert_eq!(ip_range.to_string(), "203.0.113.0-203.0.113.255");
    }

    #[test]
    fn test_protocol_to_string() {
        assert_eq!(SasProtocol::Https.to_string(), "https");
        assert_eq!(SasProtocol::HttpsAndHttp.to_string(), "https,http");
    }

    #[test]
    fn test_resource_to_string() {
        assert_eq!(SasResource::Blob.to_string(), "b");
        assert_eq!(SasResource::Container.to_string(), "c");
    }
}
