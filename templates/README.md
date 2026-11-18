# Document templates

This folder holds the lawyer-authored templates the kit renders (design §5.9). **The kit ships none**:
every legal text must come from counsel. A template is loaded only if it records its legal approval.

One JSON file per template version:

```json
{
  "id": "presale-datasheet-de", "kind": "presale_datasheet", "version": "2026-1", "language": "de-DE",
  "title": "Datenblatt {{model.name}}",
  "approvedBy": "Name of the approving lawyer", "approvedAt": "2026-11-20T00:00:00Z",
  "sections": [ { "heading": "…", "body": "… {{data.list}} …" } ]
}
```

Kinds: `presale_datasheet`, `related_service_notice`, `data_use_agreement`, `nda`, `recipient_terms`,
`decision_letter`, `authority_notice`. Rendering fails if any `{{placeholder}}` has no value.

| Kind | Placeholders |
|---|---|
| presale_datasheet | `model.name`, `maker.name`, `catalogue.version`, `data.list`, `data.formats`, `data.estimated_volume_per_day`, `data.realtime`, `data.retention`, `access.portal_url`, `access.api_url`, `access.catalogue_url` |
| related_service_notice | everything above, plus `service.relatedServiceData`, `service.holderUses`, `service.thirdPartyUse`, `service.holderIdentity`, `service.contact`, `service.competentAuthority`, `service.contractDuration` |
| data_use_agreement, nda, recipient_terms | `party.name`, `counterparty.name`, `datapoints.list` |
| decision_letter, authority_notice | the three above, plus `decision.outcome`, `decision.ground`, `decision.justification`, `request.id` |

Blank lines in a body start new paragraphs. Test-only templates live in `packages/server/test/fixtures`
and carry `"fixture": true`; they never load unless `ALLOW_FIXTURE_TEMPLATES=1`.
