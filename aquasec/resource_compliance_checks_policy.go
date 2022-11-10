package aquasec

import (
	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceComplianceChecks() *schema.Resource {
	return &schema.Resource{
		Create: resourceComplianceChecksCreate,
		Read:   resourceComplianceChecksRead,
		Update: resourceComplianceChecksUpdate,
		Delete: resourceComplianceChecksDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"author": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Optional:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Description: "description of the compliance check",
				Optional:    true,
			},
			"engine": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Optional:    true,
			},
			"kind": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Optional:    true,
			},
			"last_modified": {
				Type:        schema.TypeInt,
				Description: "Name of user account that created the policy.",
				//Optional:    true,
				Computed: true,
			},
			"path": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Required:    true,
				ForceNew:    true,
			},
			"read_only": {
				Type:        schema.TypeBool,
				Description: "Name of user account that created the policy.",
				Optional:    true,
			},
			"recommended_actions": {
				Type:        schema.TypeList,
				Description: "List of whitelisted licenses.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"script_id": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				//Optional:    true,
				Computed: true,
			},
			"severity": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Optional:    true,
			},
			"snippet": {
				Type:        schema.TypeString,
				Description: "Name of user account that created the policy.",
				Optional:    true,
			},
		},
	}
}

func resourceComplianceChecksRead(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)

	//path := d.Get("path").(string)
	/*	if _, err1 := os.Stat(path); os.IsNotExist(err1) {
		d.Set("", "")
			return nil
		}*/
	SID, err1 := ac.GetComplianceCheckList(d.Id())
	if err1 != nil {
		return err1
	}
	cc, err := ac.GetComplianceChecks(SID)

	if err == nil {
		d.Set("name", cc.Name)
		d.Set("description", cc.Description)
		d.Set("author", cc.Author)
		d.Set("engine", cc.Engine)
		d.Set("kind", cc.Kind)
		d.Set("last_modified", cc.LastModified)
		d.Set("path", cc.Path)
		d.Set("read_only", cc.Readonly)
		d.Set("recommended_actions", cc.RecommendedActions)
		d.Set("script_id", cc.ScriptID)
		d.Set("severity", cc.Severity)
		d.Set("snippet", cc.Snippet)
	} else {
		return err
	}
	return nil
}

func resourceComplianceChecksCreate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	recommended_actions := d.Get("recommended_actions").([]interface{})
	name := d.Get("name").(string)

	complaincechecks := client.ComplianceChecks{
		Name:               d.Get("name").(string),
		Description:        d.Get("description").(string),
		Author:             d.Get("author").(string),
		Engine:             d.Get("engine").(string),
		Kind:               d.Get("kind").(string),
		LastModified:       d.Get("last_modified").(int),
		Path:               d.Get("path").(string),
		Readonly:           d.Get("read_only").(bool),
		RecommendedActions: convertStringArr(recommended_actions),
		ScriptID:           d.Get("script_id").(string),
		Severity:           d.Get("severity").(string),
		Snippet:            d.Get("snippet").(string),
	}
	err := ac.CreateComplianceChecks(complaincechecks)

	if err != nil {
		return err
	}

	d.SetId(name)
	return resourceComplianceChecksRead(d, m)

}

func resourceComplianceChecksUpdate(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	name := d.Get("name").(string)

	if d.HasChanges("name", "author", "description", "engine", "kind", "last_modified", "path", "read_only", "recommended_actions", "script_id", "severity", "snippet") {
		cc := expandComplianceChecks(d)
		err := ac.UpdateComplianceChecks(cc)
		if err == nil {
			err1 := resourceComplianceChecksRead(d, m)
			if err1 == nil {
				d.SetId(name)
			} else {
				return err1
			}
		} else {
			return err
		}
	}
	return nil
}

func resourceComplianceChecksDelete(d *schema.ResourceData, m interface{}) error {
	ac := m.(*client.Client)
	SID, err1 := ac.GetComplianceCheckList(d.Id())
	if err1 != nil {
		return err1
	}
	err := ac.DeleteComplianceChecks(SID)

	if err == nil {
		d.SetId("")
	} else {
		return err
	}
	return nil
}

func expandComplianceChecks(d *schema.ResourceData) *client.ComplianceChecks {
	cc := client.ComplianceChecks{
		ScriptID: d.Get("script_id").(string),
	}

	name, ok := d.GetOk("name")
	if ok {
		cc.Name = name.(string)
	}

	description, ok := d.GetOk("description")
	if ok {
		cc.Description = description.(string)
	}

	author, ok := d.GetOk("author")
	if ok {
		cc.Author = author.(string)
	}

	engine, ok := d.GetOk("engine")
	if ok {
		cc.Engine = engine.(string)
	}

	kind, ok := d.GetOk("kind")
	if ok {
		cc.Kind = kind.(string)
	}

	last_modified, ok := d.GetOk("last_modified")
	if ok {
		cc.LastModified = last_modified.(int)
	}

	path, ok := d.GetOk("path")
	if ok {
		cc.Path = path.(string)
	}

	read_only, ok := d.GetOk("read_only")
	if ok {
		cc.Readonly = read_only.(bool)
	}

	recommended_actions, ok := d.GetOk("recommended_actions")
	if ok {
		strArr := convertStringArr(recommended_actions.([]interface{}))
		cc.RecommendedActions = strArr
	}

	severity, ok := d.GetOk("severity")
	if ok {
		cc.Severity = severity.(string)
	}

	snippet, ok := d.GetOk("snippet")
	if ok {
		cc.Snippet = snippet.(string)
	}

	return &cc
}
