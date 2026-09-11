# Playbook: CreateServiceNowTicket

Bridges Sentinel incidents into ServiceNow. Maps Sentinel severity → ITIL impact/urgency/priority, opens an INC record, tags the Sentinel incident with `snow:INC123456` for cross-linking, and posts the ticket URL back as an incident comment.

## Severity mapping (Sentinel → ServiceNow)

| Sentinel severity | Impact | Urgency | Priority |
|---|---|---|---|
| Critical | 1 | 1 | 1 (Critical) |
| High | 2 | 1 | 2 (High) |
| Medium | 2 | 2 | 3 (Moderate) |
| Low | 3 | 3 | 4 (Low) |
| Informational | 3 | 4 | 5 (Planning) |

## Deploy

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file azuredeploy.json \
  --parameters PlaybookName=CreateServiceNowTicket \
               AssignmentGroupSysId=<sys_id_of_secops_group> \
               ServiceNowInstanceUrl=https://acme.service-now.com
```

You can pull the assignment group sys_id from ServiceNow: `/api/now/table/sys_user_group?sysparm_query=name=SecOps&sysparm_fields=sys_id`.

## Bind via automation rule

Sentinel → Automation → New rule:
- Trigger: Incident created
- Condition: `Severity` ∈ {High, Critical}
- Action: Run playbook `CreateServiceNowTicket`
