# eng-governance-dashboard

---
## Repository Structure & Details (Auto-generated)

### Scopo
Popola dashboard di governance centralizzate esportando alert/advisor/health da Azure/AWS verso Log Analytics e fornendo l’infrastruttura di supporto (Logic App, identità, secret GitHub); supporta reporting continuo sullo stato di compliance.

### Cartelle
- `src/infra`: Terraform per Logic App, identità gestite, permessi e segreti GitHub necessari alle pipeline di estrazione.
- `src/scripts`: script Python che estraggono alert, advisor, health, TA da Azure/AWS e li inviano a Log Analytics (feed dati per la dashboard).

### Script
- `src/scripts/*.py`: export verso Log Analytics.

### Workflow
- `update_dashboard.yml`: aggiornamento dashboard.
- `alert_extraction.yml`: estrazione alert.

### Backend
Azure Storage `tfapporg` (rg `terraform-state-rg`, container `terraform-state`, key `eng-governance-dashboard.tfstate`).

### Note
Richiede secret/config GitHub per pipeline; backend su `tfapporg`.
