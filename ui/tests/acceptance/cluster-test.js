/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { create } from 'ember-cli-page-object';
import { settled, click, visit } from '@ember/test-helpers';
import { module, test } from 'qunit';
import { setupApplicationTest } from 'ember-qunit';
import { v4 as uuidv4 } from 'uuid';

import authPage from 'vault/tests/pages/auth';
import logout from 'vault/tests/pages/logout';
import enablePage from 'vault/tests/pages/settings/auth/enable';
import consoleClass from 'vault/tests/pages/components/console/ui-panel';

const consoleComponent = create(consoleClass);

const tokenWithPolicy = async function (name, policy) {
  await consoleComponent.runCommands([
    `write sys/policies/acl/${name} policy=${btoa(policy)}`,
    `write -field=client_token auth/token/create policies=${name}`,
  ]);

  return consoleComponent.lastLogOutput;
};

module('Acceptance | cluster', function (hooks) {
  setupApplicationTest(hooks);

  hooks.beforeEach(async function () {
    await logout.visit();
    return authPage.login();
  });

  test('hides nav item if user does not have permission', async function (assert) {
    const deny_policies_policy = `
      path "sys/policies/*" {
        capabilities = ["deny"]
      },
    `;

    const userToken = await tokenWithPolicy('hide-policies-nav', deny_policies_policy);
    await logout.visit();
    await authPage.login(userToken);
    await visit('/vault/access');

    assert.dom('[data-test-sidebar-nav-link="Policies"]').doesNotExist();
    await logout.visit();
  });

  test('it hides mfa setup if user has not entityId (ex: is a root user)', async function (assert) {
    const user = 'end-user';
    const password = 'mypassword';
    const path = `cluster-userpass-${uuidv4()}`;

    await enablePage.enable('userpass', path);
    await consoleComponent.runCommands([`write auth/${path}/users/end-user password="${password}"`]);

    await logout.visit();
    await settled();
    await authPage.loginUsername(user, password, path);
    await click('[data-test-user-menu-trigger]');
    assert.dom('[data-test-user-menu-item="mfa"]').exists();
    await logout.visit();

    await authPage.login('root');
    await settled();
    await click('[data-test-user-menu-trigger]');
    assert.dom('[data-test-user-menu-item="mfa"]').doesNotExist();
  });
});
