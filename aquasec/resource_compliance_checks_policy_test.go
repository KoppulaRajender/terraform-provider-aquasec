package aquasec

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAquasecComplainceChecks(t *testing.T) {
	t.Parallel()
	description := "Created using Terraform"
	name := acctest.RandomWithPrefix("terraform-test")
	engine := "yaml"
	path := "test.yaml"
	snippet := "apiversion"
	author := "administrator"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: CheckDestroy("aquasec_compliance_checks.terraformiap"),
		Steps: []resource.TestStep{
			{
				Config: testAccCheckComplainceChecks(name, description, author, engine, path, snippet),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckComplainceChecksExists("aquasec_compliance_checks.terraformiap"),
				),
			},
			{
				ResourceName:      "aquasec_compliance_checks.terraformiap",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckComplainceChecks(name string, description string, author string, engine string, path string, snippet string) string {
	return fmt.Sprintf(`
	resource "aquasec_compliance_checks" "terraformiap" {
		name = "%s"
		description = "%s"
		author = "%s"
		engine = "%s"
		path = "%s"
		snippet = "%s"
	}`, name, description, author, engine, path, snippet)

}

func testAccCheckComplainceChecksExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]

		if !ok {
			return NewNotFoundErrorf("%s in state", n)
		}

		if rs.Primary.ID == "" {
			return NewNotFoundErrorf("ID for %s in state", n)
		}

		return nil
	}
}
