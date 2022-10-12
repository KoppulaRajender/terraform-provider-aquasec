---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "aquasec_role_mapping Resource - terraform-provider-aquasec"
subcategory: ""
description: |-
  
---

# aquasec_role_mapping (Resource)



## Example Usage

```terraform
resource "aquasec_role_mapping" "role_mapping" {
    saml {
        role_mapping = {
            Administrator = "group1"
        }
    }
}

output "role_mapping" {
    value = aquasec_role_mapping.role_mapping
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `oauth2` (Block Set, Max: 1) Oauth2 Authentication (see [below for nested schema](#nestedblock--oauth2))
- `openid` (Block Set, Max: 1) OpenId Authentication (see [below for nested schema](#nestedblock--openid))
- `saml` (Block Set, Max: 1) SAML Authentication (see [below for nested schema](#nestedblock--saml))

### Read-Only

- `id` (String) The ID of this resource.

<a id="nestedblock--oauth2"></a>
### Nested Schema for `oauth2`

Required:

- `role_mapping` (Map of String) Role Mapping is used to define the IdP role that the user will assume in Aqua


<a id="nestedblock--openid"></a>
### Nested Schema for `openid`

Required:

- `role_mapping` (Map of String) Role Mapping is used to define the IdP role that the user will assume in Aqua


<a id="nestedblock--saml"></a>
### Nested Schema for `saml`

Required:

- `role_mapping` (Map of String) Role Mapping is used to define the IdP role that the user will assume in Aqua

