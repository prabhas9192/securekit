# Threat model: <application name>

Date: <date> · Owner: <name> · Version: <n> · Review again when: a feature that handles money, identity or personal data is added, or every six months.

## 1. Assumptions (the five framing answers)

1. What it is and where it runs:
2. Who uses it (roles, tenants):
3. Data it holds and its classification:
4. Who operates it, who has shell and database access:
5. Rules that apply (payments, health, personal data, tax):

## 2. System sketch

Components: <browser/app, API, database, cache, queue, third parties, admin tools>
Trust boundaries: <internet → API, API → database, API → vendor, staff device → API>

```
[client] --TLS--> [API] --TLS--> [database]
                    |--> [third party]
```

## 3. Assets

| Asset | Class | Where stored | Who may access |
|---|---|---|---|
| | | | |

## 4. Entry points

| Entry point | Authenticated? | Input | Notes |
|---|---|---|---|
| | | | |

## 5. Abuse cases (STRIDE-lite), ranked

| # | Abuse case ("As an attacker, I ...") | S/T/R/I/D/E | Likelihood | Impact | Control | Test that proves it | Status |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | |

## 6. Accepted risks

| Risk | Why accepted | Owner | Date | Review by |
|---|---|---|---|---|
| | | | | |

## 7. Out of scope (stated, not forgotten)

<physical security, endpoint security of staff devices, third-party internals, ...>
