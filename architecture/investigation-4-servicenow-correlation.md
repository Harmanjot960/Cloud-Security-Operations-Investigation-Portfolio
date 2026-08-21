# Diagram  — ServiceNow Alert Triage & Cross-Alert Correlation

        Windows Security Telemetry       AWS CloudTrail
                    │                         │
                    └────────────┬────────────┘
                                 ▼
                     ServiceNow SOC Queue
                                 │
                                 ▼
                       Six Security Alerts
                                 │
                                 ▼
                           Alert Triage
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
             Benign / Expected          Suspicious Alerts
                    │                         │
                    ▼                         ▼
                Resolved              Cross-Alert Correlation
                                              │
                                   ┌──────────┴──────────┐
                                   ▼                     ▼
                              Account: `mirage`         Source IP: `198.51.100.42`
                                   │                     │
                                   └──────────┬──────────┘
                                              ▼
                                      Timeline Correlation
                                              │
                                              ▼
                                  AWS + Windows Activity
                                              │
                                              ▼
                                       True Positive
                                              │
                                              ▼
                                  Escalate to Incident
                                    Response / L2
