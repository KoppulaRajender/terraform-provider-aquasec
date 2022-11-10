package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/pkg/errors"
)

type ComplianceChecks struct {
	Name               string   `json:"name"`
	Author             string   `json:"author"`
	Description        string   `json:"description"`
	Engine             string   `json:"engine"`
	Kind               string   `json:"kind"`
	LastModified       int      `json:"last_modified"`
	Path               string   `json:"path"`
	Readonly           bool     `json:"read_only"`
	RecommendedActions []string `json:"recommended_actions"`
	ScriptID           string   `json:"script_id"`
	Severity           string   `json:"severity"`
	Snippet            string   `json:"snippet"`
}

// GetComplianceChecks - returns single  Assurance Policy
func (cli *Client) GetComplianceCheckList(name string) (string, error) {
	var err error
	var response []ComplianceChecks
	cli.gorequest.Set("Authorization", "Bearer "+cli.token)

	SID := ""

	apiPath := "/api/v2/image_assurance/user_scripts?order_by=name&name=&type="
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return "", err
	}
	resp, body, errs := cli.gorequest.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		return "", errors.Wrap(getMergedError(errs), "failed getting  Assurance Policy")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetComplianceChecks from %s%s, %v ", cli.url, apiPath, err)
			return "", err
		}
		//fmt.Println(response)
		for _, v := range response {
			if v.Name == name {
				SID = v.ScriptID
			}
		}
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return "", err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return "", err
		}
		return "", fmt.Errorf("failed getting  Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	//if response.Name == "" {
	//	return nil, fmt.Errorf(" Assurance Policy not found: %s", name)
	//}
	return SID, err
}

// GetComplianceChecks - returns single  Assurance Policy
func (cli *Client) GetComplianceChecks(sid string) (*ComplianceChecks, error) {
	var err error
	var response ComplianceChecks
	cli.gorequest.Set("Authorization", "Bearer "+cli.token)

	apiPath := "/api/v2/image_assurance/user_scripts/" + sid
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	resp, body, errs := cli.gorequest.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), "failed getting  Assurance Policy")
	}
	if resp.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error calling func GetComplianceChecks from %s%s, %v ", cli.url, apiPath, err)
			return nil, err
		}
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return nil, err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return nil, err
		}
		return nil, fmt.Errorf("failed getting  Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	if response.Name == "" {
		return nil, fmt.Errorf(" Assurance Policy not found: %s", sid)
	}
	return &response, err
}

// CreateComplianceChecks - creates single Aqua  Assurance Policy

func (cli *Client) CreateComplianceChecks(complaincechecks ComplianceChecks) error {
	complaincechecklist := []ComplianceChecks{complaincechecks}

	payload, err := json.Marshal(complaincechecklist)

	apiPath := "/api/v2/image_assurance/user_scripts"
	if err != nil {
		return err
	}
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating  Assurance Policy.")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed creating  Assurance Policy. status: %v. error message: %v, body: %v, payload: %v", resp.Status, errorResponse.Message, string(body), string(payload))
	}

	return nil
}

// UpdateComplianceChecks updates an existing  Assurance Policy
func (cli *Client) UpdateComplianceChecks(assurancepolicy *ComplianceChecks) error {
	payload, err := json.Marshal(assurancepolicy)
	if err != nil {
		return err
	}

	apiPath := "/api/v2/assurance_policy/" + assurancepolicy.Name
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Put(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed modifying  Assurance Policy")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed modifying  Assurance Policy. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

// DeleteComplianceChecks removes a  Assurance Policy
func (cli *Client) DeleteComplianceChecks(sid string) error {
	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)

	apiPath := "/api/v2/image_assurance/user_scripts/" + sid
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting  Assurance Policy")
	}
	if resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed deleting  Assurance Policy, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}
