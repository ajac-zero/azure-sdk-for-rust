// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

use crate::{
    generated::clients::BlobContainerClient as GeneratedBlobContainerClient,
    generated::clients::BlobServiceClient as GeneratedBlobServiceClient,
    generated::models::{BlobServiceClientGetAccountInfoResult, KeyInfo, UserDelegationKey},
    models::{
        BlobServiceClientFindBlobsByTagsOptions, BlobServiceClientGetAccountInfoOptions,
        BlobServiceClientGetPropertiesOptions, BlobServiceClientGetStatisticsOptions,
        BlobServiceClientListContainersSegmentOptions, BlobServiceClientSetPropertiesOptions,
        BlobServiceProperties, FilterBlobSegment, ListContainersSegmentResponse,
        StorageServiceStats,
    },
    pipeline::StorageHeadersPolicy,
    BlobContainerClient, BlobServiceClientOptions,
};
use azure_core::{
    credentials::TokenCredential,
    http::{
        policies::{auth::BearerTokenAuthorizationPolicy, Policy},
        NoFormat, Pager, Pipeline, RequestContent, Response, Url, XmlFormat,
    },
    tracing, Result,
};
use std::sync::Arc;

/// A client to interact with an Azure storage account.
pub struct BlobServiceClient {
    pub(super) client: GeneratedBlobServiceClient,
}

impl GeneratedBlobServiceClient {
    /// Creates a new GeneratedBlobServiceClient from the URL of the Azure storage account.
    ///
    /// # Arguments
    ///
    /// * `blob_service_url` - The full URL of the Azure storage account, for example `https://myaccount.blob.core.windows.net/`.
    /// * `credential` - An optional implementation of [`TokenCredential`] that can provide an Entra ID token to use when authenticating.
    /// * `options` - Optional configuration for the client.
    #[tracing::new("Storage.Blob.Service")]
    pub fn from_url(
        blob_service_url: Url,
        credential: Option<Arc<dyn TokenCredential>>,
        options: Option<BlobServiceClientOptions>,
    ) -> Result<Self> {
        let mut options = options.unwrap_or_default();

        let storage_headers_policy = Arc::new(StorageHeadersPolicy);
        options
            .client_options
            .per_call_policies
            .push(storage_headers_policy);

        let per_retry_policies = if let Some(token_credential) = credential {
            if !blob_service_url.scheme().starts_with("https") {
                return Err(azure_core::Error::with_message(
                    azure_core::error::ErrorKind::Other,
                    format!("{blob_service_url} must use https"),
                ));
            }
            let auth_policy: Arc<dyn Policy> = Arc::new(BearerTokenAuthorizationPolicy::new(
                token_credential,
                vec!["https://storage.azure.com/.default"],
            ));
            vec![auth_policy]
        } else {
            Vec::default()
        };

        let pipeline = Pipeline::new(
            option_env!("CARGO_PKG_NAME"),
            option_env!("CARGO_PKG_VERSION"),
            options.client_options.clone(),
            Vec::default(),
            per_retry_policies,
            None,
        );

        Ok(Self {
            endpoint: blob_service_url,
            version: options.version,
            pipeline,
        })
    }
}

impl BlobServiceClient {
    /// Creates a new BlobServiceClient, using Entra ID authentication.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The full URL of the Azure storage account, for example `https://myaccount.blob.core.windows.net/`
    /// * `credential` - An optional implementation of [`TokenCredential`] that can provide an Entra ID token to use when authenticating.
    /// * `options` - Optional configuration for the client.
    pub fn new(
        endpoint: &str,
        credential: Option<Arc<dyn TokenCredential>>,
        options: Option<BlobServiceClientOptions>,
    ) -> Result<Self> {
        let url = Url::parse(endpoint)?;

        let client = GeneratedBlobServiceClient::from_url(url, credential, options)?;
        Ok(Self { client })
    }

    /// Returns a new instance of BlobContainerClient.
    ///
    /// # Arguments
    ///
    /// * `container_name` - The name of the container.
    pub fn blob_container_client(&self, container_name: &str) -> BlobContainerClient {
        let mut container_url = self.url().clone();
        container_url
            .path_segments_mut()
            // This should not fail as service URL has already been validated on client construction.
            .expect("Cannot be a base URL.")
            .push(container_name);

        let client = GeneratedBlobContainerClient {
            endpoint: container_url,
            pipeline: self.client.pipeline.clone(),
            version: self.client.version.clone(),
            tracer: self.client.tracer.clone(),
        };

        BlobContainerClient { client }
    }

    /// Gets the URL of the resource this client is configured for.
    pub fn url(&self) -> &Url {
        &self.client.endpoint
    }

    /// Gets the properties of a Storage account's Blob service, including Azure Storage Analytics.
    ///
    /// # Arguments
    ///
    /// * `options` - Optional configuration for the request.
    pub async fn get_properties(
        &self,
        options: Option<BlobServiceClientGetPropertiesOptions<'_>>,
    ) -> Result<Response<BlobServiceProperties, XmlFormat>> {
        self.client.get_properties(options).await
    }

    /// Returns a list of the containers under the specified Storage account.
    ///
    /// # Arguments
    ///
    /// * `options` - Optional configuration for the request.
    pub fn list_containers(
        &self,
        options: Option<BlobServiceClientListContainersSegmentOptions<'_>>,
    ) -> Result<Pager<ListContainersSegmentResponse, XmlFormat, String>> {
        self.client.list_containers_segment(options)
    }

    /// Returns a list of blobs across all containers whose tags match a given search expression.
    ///
    /// # Arguments
    ///
    /// * `filter_expression` - The expression to find blobs whose tags matches the specified condition.
    ///   eg.
    /// ```text
    /// "\"yourtagname\"='firsttag' and \"yourtagname2\"='secondtag'"
    /// ```
    ///   To specify a container, eg.
    /// ```text
    /// "@container='containerName' and \"Name\"='C'"
    /// ```
    /// See [`format_filter_expression()`](crate::format_filter_expression) for help with the expected String format.
    /// * `options` - Optional parameters for the request.
    pub async fn find_blobs_by_tags(
        &self,
        filter_expression: &str,
        options: Option<BlobServiceClientFindBlobsByTagsOptions<'_>>,
    ) -> Result<Response<FilterBlobSegment, XmlFormat>> {
        self.client
            .find_blobs_by_tags(filter_expression, options)
            .await
    }

    /// Sets properties for a Storage account's Blob service endpoint, including properties for Storage Analytics and CORS rules.
    ///
    /// # Arguments
    ///
    /// * `storage_service_properties` - The Storage service properties to set.
    /// * `options` - Optional configuration for the request.
    pub async fn set_properties(
        &self,
        storage_service_properties: RequestContent<BlobServiceProperties, XmlFormat>,
        options: Option<BlobServiceClientSetPropertiesOptions<'_>>,
    ) -> Result<Response<(), NoFormat>> {
        self.client
            .set_properties(storage_service_properties, options)
            .await
    }

    /// Gets information related to the Storage account.
    /// This includes the `sku_name` and `account_kind`.
    ///
    /// # Arguments
    ///
    /// * `options` - Optional configuration for the request.
    pub async fn get_account_info(
        &self,
        options: Option<BlobServiceClientGetAccountInfoOptions<'_>>,
    ) -> Result<Response<BlobServiceClientGetAccountInfoResult, NoFormat>> {
        self.client.get_account_info(options).await
    }

    /// Retrieves statistics related to replication for the Blob service. It is only available on the secondary location endpoint
    /// when read-access geo-redundant replication is enabled for the storage account.
    ///
    /// # Arguments
    ///
    /// * `options` - Optional configuration for the request.
    pub async fn get_statistics(
        &self,
        options: Option<BlobServiceClientGetStatisticsOptions<'_>>,
    ) -> Result<Response<StorageServiceStats, XmlFormat>> {
        self.client.get_statistics(options).await
    }

    /// Retrieves a user delegation key for creating SAS tokens.
    ///
    /// The user delegation key is used to sign SAS tokens with Entra ID credentials
    /// instead of storage account keys. This provides better security and auditability.
    ///
    /// User delegation keys are valid for up to 7 days from the start time.
    ///
    /// # Arguments
    ///
    /// * `start` - The date-time when the key becomes active
    /// * `expiry` - The date-time when the key expires (maximum 7 days from start)
    /// * `options` - Optional configuration for the request
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use azure_storage_blob::BlobServiceClient;
    /// # use azure_identity::DefaultAzureCredential;
    /// # use azure_core::time::OffsetDateTime;
    /// # use std::{sync::Arc, time::Duration};
    /// # async fn example() -> azure_core::Result<()> {
    /// # let credential = Arc::new(DefaultAzureCredential::new()?);
    /// # let service_client = BlobServiceClient::new(
    /// #     "https://myaccount.blob.core.windows.net",
    /// #     Some(credential),
    /// #     None,
    /// # )?;
    /// let start = OffsetDateTime::now_utc();
    /// let expiry = start + Duration::from_secs(3600); // 1 hour
    ///
    /// let key = service_client
    ///     .get_user_delegation_key(start, expiry, None)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_user_delegation_key(
        &self,
        start: azure_core::time::OffsetDateTime,
        expiry: azure_core::time::OffsetDateTime,
        options: Option<crate::models::BlobServiceClientGetUserDelegationKeyOptions<'_>>,
    ) -> Result<Response<UserDelegationKey, XmlFormat>> {
        // Format times in ISO 8601 / RFC 3339 format
        let start_str = start
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| {
                azure_core::Error::with_message(
                    azure_core::error::ErrorKind::DataConversion,
                    format!("failed to format start time: {}", e),
                )
            })?;

        let expiry_str = expiry
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| {
                azure_core::Error::with_message(
                    azure_core::error::ErrorKind::DataConversion,
                    format!("failed to format expiry time: {}", e),
                )
            })?;

        // Create KeyInfo
        let key_info = KeyInfo {
            start: Some(start_str),
            expiry: Some(expiry_str),
        };

        // Convert to RequestContent
        let request_content = RequestContent::try_from(key_info)?;

        // Call the generated client method
        self.client
            .get_user_delegation_key(request_content, options)
            .await
    }
}
