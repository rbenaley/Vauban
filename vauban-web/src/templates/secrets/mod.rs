/// VAUBAN Web - Vault Secrets templates (admin zone `/vault/secrets`).
///
/// Self-contained section: organisational secrets, secret groups and
/// secret access rules. Every page is gated by `vault_secrets:manage`
/// (route_layer + in-handler re-check).
pub mod groups;
pub mod rules;
#[allow(clippy::module_inception)]
pub mod secrets;

pub use groups::{
    GroupSecretItem, SecretGroupCreateTemplate, SecretGroupDetailData, SecretGroupDetailTemplate,
    SecretGroupEditData, SecretGroupEditTemplate, SecretGroupForm, SecretGroupItem,
    SecretGroupListTemplate, SecretOption,
};
pub use rules::{
    SecretGroupOption, SecretRuleCreateTemplate, SecretRuleDetailData, SecretRuleDetailTemplate,
    SecretRuleEditData, SecretRuleEditTemplate, SecretRuleForm, SecretRuleItem,
    SecretRuleListTemplate,
};
pub use secrets::{
    SecretCreateForm, SecretCreateTemplate, SecretDetailData, SecretDetailTemplate, SecretEditData,
    SecretEditTemplate, SecretGroupRef, SecretItem, SecretListTemplate,
};
