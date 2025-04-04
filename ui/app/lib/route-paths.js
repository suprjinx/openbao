/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

export const INIT = 'vault.cluster.init';
export const UNSEAL = 'vault.cluster.unseal';
export const AUTH = 'vault.cluster.auth';
export const REDIRECT = 'vault.cluster.redirect';
export const CLUSTER = 'vault.cluster';
export const CLUSTER_INDEX = 'vault.cluster.index';
export const OIDC_CALLBACK = 'vault.cluster.oidc-callback';
export const OIDC_PROVIDER = 'vault.cluster.oidc-provider';
export const NS_OIDC_PROVIDER = 'vault.cluster.oidc-provider-ns';
export const EXCLUDED_REDIRECT_URLS = ['/vault/logout'];
