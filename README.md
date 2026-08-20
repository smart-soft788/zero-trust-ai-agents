# Reference Implementation: Zero Trust AI Agents (v5.0)

**Версия:** v5.0  
**Дата релиза:** 20 августа 2026 г.  
**Разработчик:** Смарт-Софт  

---

## 📦 Состав файлов

* `checklist/zero_trust_ai_agents_final_kit_v5.pdf`
* `checklist/zero_trust_ai_agents_final_kit_v5.docx`
* `policies/rag_policy_zero_trust_v5.rego`
* `policies/rag_policy_zero_trust_v5_test.rego`
* `incident-response/zero_trust_ai_agents_runbook_v5.pdf`
* `incident-response/zero_trust_ai_agents_runbook_v5.docx`
* `incident-response/prompt_injection_incident_log_v5.pdf`
* `incident-response/prompt_injection_incident_log_v5.docx`
* `testing/zero_trust_ai_agents_tests_dashboard_v5.xlsx`
* `testing/zero_trust_dashboard_v5_preview.png`
* `bundle/zero_trust_ai_agents_v5_bundle.zip`

---

## ⚠️ Ограничения Reference Implementation

1. **Демонстрационный характер политик:** Представленные OPA-политики (`.rego`) являются эталонным шаблоном и требуют адаптации под конкретную инфраструктуру, ролевую модель (RBAC/ABAC) и API вашей организации.
2. **Изоляция окружения:** Шаблоны реагирования (Runbook) предполагают наличие настроенных точек соблюдения политик (PEP) и PDP (Policy Decision Point) в вашей сети.
3. **Отсутствие боевых токенов:** Все примеры конфигураций, идентификаторы агентов и сессий содержат обезличенные тестовые значения.

---

## 🔐 Контрольная сумма

* **Архив:** `zero_trust_ai_agents_v5_bundle.zip`
* **SHA-256:** `f34a07d157adee99ac1a118489f926131744bb9b89986acf5994b07593e5f0a5`
