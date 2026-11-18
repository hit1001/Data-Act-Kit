import { createAuthenticator, discoverJwksUri } from '../auth.ts';
import { readKey } from '../config.ts';
import { TemplateStore } from '../documents.ts';
import { buildApp } from '../http.ts';
import { DynSec, KeycloakAdmin } from '../integrations.ts';
import { SseHub, TOPIC_READINGS, TOPIC_REVOKED, type LiveMessage } from '../live.ts';
import { boot, connectMqtt } from '../runtime.ts';

const rt = boot();
const { config } = rt;
const hub = new SseHub();
const mqtt = await connectMqtt(config, `dak-api-${process.pid}`, { clean: true });
await mqtt.subscribeAsync([`${TOPIC_READINGS}+`, TOPIC_REVOKED], { qos: 1 });
mqtt.on('message', (topic, buf) => {
  if (topic === TOPIC_REVOKED) hub.revoke(buf.toString('utf8'));
  else if (topic.startsWith(TOPIC_READINGS)) hub.deliver(JSON.parse(buf.toString('utf8')) as LiveMessage);
});
const app = buildApp({
  config, pool: rt.pool, keyring: rt.keyring, kek: rt.kek, hub, mqtt, dynsec: new DynSec(mqtt),
  auth: createAuthenticator(rt.pool, config.oidc.issuer, config.oidc.audience, await discoverJwksUri(config.oidc.issuer, config.oidc.discoveryUrl)),
  templates: new TemplateStore(config.templatesDir, config.allowFixtureTemplates),
  fingerprintSecret: readKey(config.fingerprintSecretFile).toString('hex'),
  keycloak: config.keycloakAdmin ? new KeycloakAdmin(config.keycloakAdmin) : null,
});
await app.listen({ host: '0.0.0.0', port: config.httpPort });
for (const sig of ['SIGINT', 'SIGTERM'] as const) process.once(sig, () => { void app.close().then(() => { mqtt.end(); return rt.pool.end(); }); });
