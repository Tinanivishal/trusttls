package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trustctl/trusttls/internal/acme"
)

type AccountCredentials struct {
	Email           string            `json:"email"`
	Server          string            `json:"server"`
	EABKID          string            `json:"eab_kid,omitempty"`
	EABHMACKey      string            `json:"eab_hmac_key,omitempty"`
	HMACID          string            `json:"hmac_id,omitempty"`
	HMACKey         string            `json:"hmac_key,omitempty"`
	APIKey          string            `json:"api_key,omitempty"`
	AccountID       string            `json:"account_id,omitempty"`
	OrganizationID  string            `json:"organization_id,omitempty"`
	Provider        string            `json:"provider"` // "letsencrypt" or "digicert"
}

type AccountManager struct {
	baseDir string
}

func NewAccountManager(baseDir string) *AccountManager {
	return &AccountManager{baseDir: baseDir}
}

func (am *AccountManager) SaveAccount(email string, creds AccountCredentials) error {
	accountDir := filepath.Join(am.baseDir, "accounts", creds.Provider, email)
	if err := ensureDir(accountDir, 0700); err != nil {
		return err
	}

	credsFile := filepath.Join(accountDir, "credentials.json")
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(credsFile, data, 0600)
}

func (am *AccountManager) LoadAccount(email, provider string) (*AccountCredentials, error) {
	credsFile := filepath.Join(am.baseDir, "accounts", provider, email, "credentials.json")
	
	data, err := os.ReadFile(credsFile)
	if err != nil {
		return nil, err
	}

	var creds AccountCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}

	return &creds, nil
}

func (am *AccountManager) ListAccounts(provider string) ([]string, error) {
	providerDir := filepath.Join(am.baseDir, "accounts", provider)
	entries, err := os.ReadDir(providerDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var emails []string
	for _, entry := range entries {
		if entry.IsDir() {
			emails = append(emails, entry.Name())
		}
	}

	return emails, nil
}

func (am *AccountManager) GetDigiCertACMEConfig(email string) (*acme.DigiCertEABConfig, error) {
	creds, err := am.LoadAccount(email, "digicert")
	if err != nil {
		return nil, err
	}

	if creds.Provider != "digicert" {
		return nil, fmt.Errorf("account is not a DigiCert account")
	}

	return &acme.DigiCertEABConfig{
		ServerURL:   creds.Server,
		EABKID:      creds.EABKID,
		EABHMACKey:  creds.EABHMACKey,
		Email:       creds.Email,
		BaseDir:     am.baseDir,
	}, nil
}

func (am *AccountManager) SaveDigiCertACMEAccount(email, server, eabKID, eabHMACKey, accountID, organizationID string) error {
	creds := AccountCredentials{
		Email:          email,
		Server:         server,
		EABKID:         eabKID,
		EABHMACKey:     eabHMACKey,
		AccountID:      accountID,
		OrganizationID: organizationID,
		Provider:       "digicert",
	}

	return am.SaveAccount(email, creds)
}

func (am *AccountManager) GetDigiCertConfig(email string) (*acme.DigiCertConfig, error) {
	creds, err := am.LoadAccount(email, "digicert")
	if err != nil {
		return nil, err
	}

	if creds.Provider != "digicert" {
		return nil, fmt.Errorf("account is not a DigiCert account")
	}

	return &acme.DigiCertConfig{
		ServerURL:       creds.Server,
		HMACID:          creds.HMACID,
		HMACKey:         creds.HMACKey,
		APIKey:          creds.APIKey,
		AccountID:       creds.AccountID,
		OrganizationID:  creds.OrganizationID,
	}, nil
}

func (am *AccountManager) SaveDigiCertAccount(email, server, hmacID, hmacKey, apiKey, accountID, organizationID string) error {
	creds := AccountCredentials{
		Email:          email,
		Server:         server,
		HMACID:         hmacID,
		HMACKey:        hmacKey,
		APIKey:         apiKey,
		AccountID:      accountID,
		OrganizationID: organizationID,
		Provider:       "digicert",
	}

	return am.SaveAccount(email, creds)
}

func (am *AccountManager) SaveLetsEncryptAccount(email, server string) error {
	creds := AccountCredentials{
		Email:    email,
		Server:   server,
		Provider: "letsencrypt",
	}

	return am.SaveAccount(email, creds)
}
