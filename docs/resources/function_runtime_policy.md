---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "aquasec_function_runtime_policy Resource - terraform-provider-aquasec"
subcategory: ""
description: |-
  
---

# Resource `aquasec_function_runtime_policy`





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **name** (String) Name of the function runtime policy

### Optional

- **application_scopes** (List of String) Indicates the application scope of the service.
- **block_malicious_executables** (Boolean) If true, prevent creation of malicious executables in functions during their runtime post invocation.
- **blocked_executables** (List of String) List of executables that are prevented from running in containers.
- **description** (String) The description of the function runtime policy
- **enabled** (Boolean) Indicates if the runtime policy is enabled or not.
- **enforce** (Boolean) Indicates that policy should effect container execution (not just for audit).
- **honeypot_access_key** (String) Honeypot User ID (Access Key)
- **honeypot_apply_on** (List of String) List of options to apply the honeypot on (Environment Vairable, Layer, File)
- **honeypot_secret_key** (String, Sensitive) Honeypot User Password (Secret Key)
- **honeypot_serverless_app_name** (String) Serverless application name
- **id** (String) The ID of this resource.
- **scope_expression** (String) Logical expression of how to compute the dependency of the scope variables.
- **scope_variables** (Block List) List of scope attributes. (see [below for nested schema](#nestedblock--scope_variables))

### Read-only

- **author** (String) Username of the account that created the service.

<a id="nestedblock--scope_variables"></a>
### Nested Schema for `scope_variables`

Required:

- **attribute** (String) Class of supported scope.
- **value** (String) Value assigned to the attribute.

