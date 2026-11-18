// Domain types shared by the server and the edge connector (design §5, §6).

export const ROLES = [
  'maker_admin', 'catalogue_reviewer', 'legal_officer', 'customer_admin', 'customer_user', 'recipient',
] as const;
export type Role = (typeof ROLES)[number];

export type OrgKind = 'maker' | 'customer' | 'recipient';

/** Enterprise size per Recommendation 2003/361/EC, as referenced by Data Act Art. 7. */
export type EnterpriseSize = 'micro' | 'small' | 'medium' | 'large';

export type Channel = 'rest' | 'sse' | 'webhook' | 'mqtt';
export const CHANNELS: readonly Channel[] = ['rest', 'sse', 'webhook', 'mqtt'];

export type DataType = 'number' | 'boolean' | 'string';

export interface Principal {
  readonly id: string;
  readonly orgId: string;
  readonly orgKind: OrgKind;
  readonly roles: readonly Role[];
  /** OAuth client-credentials token (machine client) rather than a person. */
  readonly isMachineClient: boolean;
  /** OAuth scopes on the token; machine clients must carry `grant:<id>` for each grant they use. */
  readonly scopes: readonly string[];
}

export interface DatapointFacts {
  readonly id: string;
  readonly modelId: string;
  readonly tradeSecret: boolean;
  readonly personalData: boolean;
  readonly status: 'draft' | 'published';
}

export interface MachineFacts {
  readonly id: string;
  readonly modelId: string;
  readonly ownerOrgId: string | null;
}

export interface GrantFacts {
  readonly id: string;
  readonly customerOrgId: string;
  readonly recipientOrgId: string;
  readonly datapointIds: readonly string[];
  readonly channels: readonly Channel[];
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
  /** Recipient accepted the terms bound to its category (R14). */
  readonly termsAccepted: boolean;
}

export interface ReadingInput {
  readonly datapointId: string;
  readonly ts: string; // ISO 8601
  readonly value: number | boolean | string;
}

/** MQTT payload published by the edge connector on `devices/<deviceId>/readings`. */
export interface EdgeBatch {
  readonly deviceId: string;
  readonly seq: number;
  readonly readings: readonly ReadingInput[];
}
