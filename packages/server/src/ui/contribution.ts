/**
 * The resolver's management surfaces, as an `AppPort/ui/1` contribution.
 *
 * The UI contract is owned by `@appport/protocol`; this module only describes the resolver's pages in that
 * shape and validates the result with the protocol's own validator, as AppPort Services does. The AppPort
 * server serves it at `GET /v1/ui`, filtered by the caller's capabilities: the resolver asserts none for a
 * caller, so discovery shows only the capability-free overview. Every page authenticates and authorizes
 * its own caller.
 */

import { UI_PROTOCOL_ID, validateUiContribution, type UiContribution } from '@appport/protocol';
import { CAPABILITIES } from '@appport/resolver-core';

export const VERSION = '0.1.0';

export interface UiPage {
  readonly id: string;
  readonly title: string;
  readonly route: string;
  readonly order: number;
  /** What the page is for, shown on the overview. */
  readonly description: string;
  /** The resolver capabilities the page drives. */
  readonly capabilities: readonly string[];
}

export const PAGES: readonly UiPage[] = [
  { id: 'overview', title: 'Resolver', route: '/resolver', order: 0, description: 'Stable names for everything that changes.', capabilities: [] },
  {
    id: 'references',
    title: 'References',
    route: '/references',
    order: 10,
    description: 'Every reference, its binding, revisions and history. Change, roll back or revoke.',
    capabilities: [CAPABILITIES.list, CAPABILITIES.resolve, CAPABILITIES.history, CAPABILITIES.put, CAPABILITIES.rollback, CAPABILITIES.revoke],
  },
  {
    id: 'models',
    title: 'Models',
    route: '/models',
    order: 20,
    description: 'Model aliases: provider, model and traffic split. Retarget without a redeploy.',
    capabilities: [CAPABILITIES.list, CAPABILITIES.resolve, CAPABILITIES.put],
  },
  {
    id: 'secrets',
    title: 'Secrets',
    route: '/secrets',
    order: 30,
    description: 'API keys and credentials. Values go into the vault and never come back to this UI.',
    capabilities: [CAPABILITIES.list, CAPABILITIES.resolve, CAPABILITIES.put, CAPABILITIES.revoke],
  },
  {
    id: 'access',
    title: 'Access',
    route: '/access',
    order: 40,
    description: 'API keys for applications, and the grants that say what each may read, reveal or change.',
    capabilities: [CAPABILITIES.listKeys, CAPABILITIES.createKey, CAPABILITIES.revokeKey, CAPABILITIES.grants, CAPABILITIES.grant, CAPABILITIES.ungrant],
  },
];

const GROUP = 'Resolver';

export function createUiContribution(): UiContribution {
  return validateUiContribution({
    protocol: UI_PROTOCOL_ID,
    product: { id: 'appport-resolver', version: VERSION },
    surfaces: PAGES.map(({ id, title, route, capabilities }) => ({ id, title, route, capabilities: [...capabilities] })),
    navigation: PAGES.map(({ id, title, order }) => ({ id: `resolver.${id}`, label: title, group: GROUP, order, surface: id })),
    // Discovery names pages and the capabilities they need, and grants nothing.
    composition: { requires: [] },
  });
}
