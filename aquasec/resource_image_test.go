package aquasec

import (
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/terraform-provider-aquasec/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var image = client.Image{
	Registry:   acctest.RandomWithPrefix("terraform-test"),
	Repository: "elasticsearch",
	Tag:        "6.4.2",
	Disallowed: false,
}

func TestResourceAquasecImageCreate(t *testing.T) {
	rootRef := imageResourceRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getImageResource(&image),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttr(rootRef, "scan_status", "finished"),
					resource.TestCheckResourceAttr(rootRef, "disallowed", "false"),
					resource.TestCheckResourceAttrSet(rootRef, "created"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "os", "centos"),
					resource.TestCheckResourceAttr(rootRef, "os_version", "7"),
					resource.TestCheckResourceAttrSet(rootRef, "docker_version"),
					resource.TestCheckResourceAttrSet(rootRef, "architecture"),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
					resource.TestCheckResourceAttrSet(rootRef, "environment_variables.0"),
					resource.TestCheckResourceAttrSet(rootRef, "vulnerabilities.0.name"),
					resource.TestCheckResourceAttrSet(rootRef, "history.0.created"),
					resource.TestCheckResourceAttrSet(rootRef, "assurance_checks_performed.0.control"),
				),
			},
		},
	})
}

func TestResourceAquasecImageAllow(t *testing.T) {
	rootRef := imageResourceRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getImageResource(&image),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttr(rootRef, "scan_status", "finished"),
					resource.TestCheckResourceAttr(rootRef, "disallowed", "false"),
					resource.TestCheckResourceAttrSet(rootRef, "created"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "os", "centos"),
					resource.TestCheckResourceAttr(rootRef, "os_version", "7"),
					resource.TestCheckResourceAttrSet(rootRef, "docker_version"),
					resource.TestCheckResourceAttrSet(rootRef, "architecture"),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
					resource.TestCheckResourceAttrSet(rootRef, "environment_variables.0"),
					resource.TestCheckResourceAttrSet(rootRef, "vulnerabilities.0.name"),
					resource.TestCheckResourceAttrSet(rootRef, "history.0.created"),
					resource.TestCheckResourceAttrSet(rootRef, "assurance_checks_performed.0.control"),
				),
			},
			{
				Config: getImageResourceAllow(&image, "This image is whitelisted from terraform test."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttr(rootRef, "scan_status", "finished"),
					resource.TestCheckResourceAttrSet(rootRef, "created"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "os", "centos"),
					resource.TestCheckResourceAttr(rootRef, "os_version", "7"),
					resource.TestCheckResourceAttrSet(rootRef, "docker_version"),
					resource.TestCheckResourceAttrSet(rootRef, "architecture"),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
					resource.TestCheckResourceAttrSet(rootRef, "environment_variables.0"),
					resource.TestCheckResourceAttrSet(rootRef, "vulnerabilities.0.name"),
					resource.TestCheckResourceAttrSet(rootRef, "history.0.created"),
					resource.TestCheckResourceAttrSet(rootRef, "assurance_checks_performed.0.control"),
					resource.TestCheckResourceAttr(rootRef, "disallowed", "false"),
					resource.TestCheckResourceAttr(rootRef, "whitelisted", "true"),
					resource.TestCheckResourceAttr(rootRef, "blacklisted", "false"),
					resource.TestCheckResourceAttr(rootRef, "permission_comment", "This image is whitelisted from terraform test."),
				),
			},
		},
	})
}

func TestResourceAquasecImageBlock(t *testing.T) {
	rootRef := imageResourceRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getImageResource(&image),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttr(rootRef, "scan_status", "finished"),
					resource.TestCheckResourceAttr(rootRef, "disallowed", "false"),
					resource.TestCheckResourceAttrSet(rootRef, "created"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "os", "centos"),
					resource.TestCheckResourceAttr(rootRef, "os_version", "7"),
					resource.TestCheckResourceAttrSet(rootRef, "docker_version"),
					resource.TestCheckResourceAttrSet(rootRef, "architecture"),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
					resource.TestCheckResourceAttrSet(rootRef, "environment_variables.0"),
					resource.TestCheckResourceAttrSet(rootRef, "vulnerabilities.0.name"),
					resource.TestCheckResourceAttrSet(rootRef, "history.0.created"),
					resource.TestCheckResourceAttrSet(rootRef, "assurance_checks_performed.0.control"),
				),
			},
			{
				Config: getImageResourceBlock(&image, "This image is blacklisted from terraform test."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttr(rootRef, "scan_status", "finished"),
					resource.TestCheckResourceAttrSet(rootRef, "created"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "os", "centos"),
					resource.TestCheckResourceAttr(rootRef, "os_version", "7"),
					resource.TestCheckResourceAttrSet(rootRef, "docker_version"),
					resource.TestCheckResourceAttrSet(rootRef, "architecture"),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
					resource.TestCheckResourceAttrSet(rootRef, "environment_variables.0"),
					resource.TestCheckResourceAttrSet(rootRef, "vulnerabilities.0.name"),
					resource.TestCheckResourceAttrSet(rootRef, "history.0.created"),
					resource.TestCheckResourceAttrSet(rootRef, "assurance_checks_performed.0.control"),
					resource.TestCheckResourceAttr(rootRef, "disallowed", "true"),
					resource.TestCheckResourceAttr(rootRef, "blacklisted", "true"),
					resource.TestCheckResourceAttr(rootRef, "whitelisted", "false"),
					resource.TestCheckResourceAttr(rootRef, "permission_comment", "This image is blacklisted from terraform test."),
				),
			},
		},
	})
}

func TestResourceAquasecImageAllowAndBlock(t *testing.T) {
	rootRef := imageResourceRef("test")
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getImageResource(&image),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttr(rootRef, "scan_status", "finished"),
					resource.TestCheckResourceAttr(rootRef, "disallowed", "false"),
					resource.TestCheckResourceAttrSet(rootRef, "created"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "os", "centos"),
					resource.TestCheckResourceAttr(rootRef, "os_version", "7"),
					resource.TestCheckResourceAttrSet(rootRef, "docker_version"),
					resource.TestCheckResourceAttrSet(rootRef, "architecture"),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
					resource.TestCheckResourceAttrSet(rootRef, "environment_variables.0"),
					resource.TestCheckResourceAttrSet(rootRef, "vulnerabilities.0.name"),
					resource.TestCheckResourceAttrSet(rootRef, "history.0.created"),
					resource.TestCheckResourceAttrSet(rootRef, "assurance_checks_performed.0.control"),
				),
			},
			{
				Config: getImageResourceAllow(&image, "This image is whitelisted from terraform test."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttr(rootRef, "scan_status", "finished"),
					resource.TestCheckResourceAttrSet(rootRef, "created"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "os", "centos"),
					resource.TestCheckResourceAttr(rootRef, "os_version", "7"),
					resource.TestCheckResourceAttrSet(rootRef, "docker_version"),
					resource.TestCheckResourceAttrSet(rootRef, "architecture"),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
					resource.TestCheckResourceAttrSet(rootRef, "environment_variables.0"),
					resource.TestCheckResourceAttrSet(rootRef, "vulnerabilities.0.name"),
					resource.TestCheckResourceAttrSet(rootRef, "history.0.created"),
					resource.TestCheckResourceAttrSet(rootRef, "assurance_checks_performed.0.control"),
					resource.TestCheckResourceAttr(rootRef, "disallowed", "false"),
					resource.TestCheckResourceAttr(rootRef, "whitelisted", "true"),
					resource.TestCheckResourceAttr(rootRef, "blacklisted", "false"),
					resource.TestCheckResourceAttr(rootRef, "permission_comment", "This image is whitelisted from terraform test."),
				),
			},
			{
				Config: getImageResourceBlock(&image, "This image is blacklisted from terraform test."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rootRef, "registry", image.Registry),
					resource.TestCheckResourceAttr(rootRef, "registry_type", "HUB"),
					resource.TestCheckResourceAttr(rootRef, "repository", image.Repository),
					resource.TestCheckResourceAttr(rootRef, "tag", image.Tag),
					resource.TestCheckResourceAttr(rootRef, "scan_status", "finished"),
					resource.TestCheckResourceAttrSet(rootRef, "created"),
					resource.TestCheckResourceAttrSet(rootRef, "scan_date"),
					resource.TestCheckResourceAttr(rootRef, "scan_error", ""),
					resource.TestCheckResourceAttrSet(rootRef, "critical_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "high_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "medium_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "low_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "negligible_vulnerabilities"),
					resource.TestCheckResourceAttrSet(rootRef, "total_vulnerabilities"),
					resource.TestCheckResourceAttr(rootRef, "author", os.Getenv("AQUA_USER")),
					resource.TestCheckResourceAttr(rootRef, "os", "centos"),
					resource.TestCheckResourceAttr(rootRef, "os_version", "7"),
					resource.TestCheckResourceAttrSet(rootRef, "docker_version"),
					resource.TestCheckResourceAttrSet(rootRef, "architecture"),
					resource.TestCheckResourceAttrSet(rootRef, "image_size"),
					resource.TestCheckResourceAttrSet(rootRef, "environment_variables.0"),
					resource.TestCheckResourceAttrSet(rootRef, "vulnerabilities.0.name"),
					resource.TestCheckResourceAttrSet(rootRef, "history.0.created"),
					resource.TestCheckResourceAttrSet(rootRef, "assurance_checks_performed.0.control"),
					resource.TestCheckResourceAttr(rootRef, "disallowed", "true"),
					resource.TestCheckResourceAttr(rootRef, "blacklisted", "true"),
					resource.TestCheckResourceAttr(rootRef, "whitelisted", "false"),
					resource.TestCheckResourceAttr(rootRef, "permission_comment", "This image is blacklisted from terraform test."),
				),
			},
		},
	})
}

func imageResourceRef(name string) string {
	return fmt.Sprintf("aquasec_image.%s", name)
}

func getImageResource(image *client.Image) string {
	return getRegistry(image.Registry) + fmt.Sprintf(`
	resource "aquasec_image" "test" {
		registry = aquasec_integration_registry.demo.id
		repository = "%s"
		tag = "%s"
	}
`, image.Repository, image.Tag)
}

func getImageResourceAllow(image *client.Image, comment string) string {
	return getRegistry(image.Registry) + fmt.Sprintf(`
	resource "aquasec_image" "test" {
		registry = aquasec_integration_registry.demo.id
		repository = "%s"
		tag = "%s"
		allow_image = true
		permission_modification_comment = "%s"
	}
`, image.Repository, image.Tag, comment)
}

func getImageResourceBlock(image *client.Image, comment string) string {
	return getRegistry(image.Registry) + fmt.Sprintf(`
	resource "aquasec_image" "test" {
		registry = aquasec_integration_registry.demo.id
		repository = "%s"
		tag = "%s"
		block_image = true
		permission_modification_comment = "%s"
	}
`, image.Repository, image.Tag, comment)
}

func getRegistry(name string) string {
	return fmt.Sprintf(`
	resource "aquasec_integration_registry" "demo" {
		name = "%s"
		type = "HUB"
		prefixes = [
			""
		]
	}
`, name)
}
