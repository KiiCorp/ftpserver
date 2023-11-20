// Package config provides all the config management
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	log "github.com/fclairamb/go-log"
	"github.com/tidwall/sjson"

	"github.com/fclairamb/ftpserver/config/confpar"
	"github.com/fclairamb/ftpserver/fs"
	"golang.org/x/crypto/bcrypt"
)

// ErrUnknownUser is returned when the provided user cannot be identified through our authentication mechanism
var ErrUnknownUser = errors.New("unknown user")

// Config provides the general server config
type Config struct {
	fileName string
	logger   log.Logger
	Content  *confpar.Content

	dynamicContentS3Bucket  string
	dynamicContentS3Root    string
	dynamicContentAuthUrl   string
	dynamicContentTenantUrl string
}

// NewConfig creates a new config instance
func NewConfig(fileName string, logger log.Logger) (*Config, error) {
	if fileName == "" {
		fileName = "ftpserver.json"
	}

	config := &Config{
		fileName: fileName,
		logger:   logger,
	}

	if err := config.Load(); err != nil {
		return nil, err
	}
	config.dynamicContentS3Bucket = os.Getenv("DYNAMIC_CONTENT_S3_BUCKET")
	config.dynamicContentS3Root = os.Getenv("DYNAMIC_CONTENT_S3_ROOT")
	if config.dynamicContentS3Root == "" {
		config.dynamicContentS3Root = "root"
	}
	config.dynamicContentAuthUrl = os.Getenv("DYNAMIC_CONTENT_AUTH_URL")
	return config, nil
}

// FromContent creates a new config instance from a pre-created Content and logger. The
// fileName should indicate origin of the given Content, but the file will never be opened.
func FromContent(content *confpar.Content, fileName string, logger log.Logger) (*Config, error) {
	c := &Config{
		fileName: fileName,
		logger:   logger,
		Content:  content,
	}

	if err := c.Prepare(); err != nil {
		return nil, err
	}

	return c, nil
}

// Load the config
func (c *Config) Load() error {
	file, errOpen := os.Open(c.fileName)

	if errOpen != nil {
		return errOpen
	}

	defer func() {
		if errClose := file.Close(); errClose != nil {
			c.logger.Error("Cannot close config file", "err", errClose)
		}
	}()

	decoder := json.NewDecoder(file)

	// We parse and then copy to allow hot-reload in the future
	var content confpar.Content
	if errDecode := decoder.Decode(&content); errDecode != nil {
		c.logger.Error("Cannot decode file", "err", errDecode)

		return errDecode
	}

	c.Content = &content

	if c.Content.HashPlaintextPasswords {
		c.HashPlaintextPasswords()
	}

	return c.Prepare()
}

func (c *Config) HashPlaintextPasswords() error {

	json, errReadFile := os.ReadFile(c.fileName)
	if errReadFile != nil {
		c.logger.Error("Cannot read config file!", "err", errReadFile)
		return errReadFile
	}

	save := false
	for i, a := range c.Content.Accesses {
		if a.User == "anonymous" && a.Pass == "*" {
			continue
		}
		_, errCost := bcrypt.Cost([]byte(a.Pass))
		if errCost != nil {
			//This password is not hashed
			hash, errHash := bcrypt.GenerateFromPassword([]byte(a.Pass), 10)
			if errHash == nil {
				modified, errJsonSet := sjson.Set(string(json), "accesses."+fmt.Sprint(i)+".pass", string(hash))
				c.Content.Accesses[i].Pass = string(hash)
				if errJsonSet == nil {
					save = true
					json = []byte(modified)
				}
			}
		}
	}
	if save {
		errWriteFile := os.WriteFile(c.fileName, json, 0644)
		if errWriteFile != nil {
			c.logger.Error("Cannot write config file!", "err", errWriteFile)
			return errWriteFile
		}
	}
	return nil
}

// Prepare the config before using it
func (c *Config) Prepare() error {
	ct := c.Content
	if ct.ListenAddress == "" {
		ct.ListenAddress = "0.0.0.0:2121"
	}

	if publicHost := os.Getenv("PUBLIC_HOST"); publicHost != "" {
		ct.PublicHost = publicHost
	}

	return nil
}

// CheckAccesses checks all accesses
func (c *Config) CheckAccesses() error {
	for _, access := range c.Content.Accesses {
		_, errAccess := fs.LoadFs(access, c.logger)
		if errAccess != nil {
			c.logger.Error("Config: Invalid access !", "err", errAccess, "username", access.User, "fs", access.Fs)

			return errAccess
		}
	}

	return nil
}

// GetAccess return a file system access given some credentials
func (c *Config) GetAccess(user string, pass string) (*confpar.Access, error) {
	for _, a := range c.Content.Accesses {
		if a.User == user {
			_, errCost := bcrypt.Cost([]byte(a.Pass))
			if errCost == nil {
				//This user's password is bcrypted
				errCompare := bcrypt.CompareHashAndPassword([]byte(a.Pass), []byte(pass))
				if errCompare == nil {
					return a, nil
				}
			} else {
				//This user's password is plain-text
				if a.Pass == pass || (a.User == "anonymous" && a.Pass == "*") {
					return a, nil
				}
			}
		}
	}
	if c.isDynamicContentEnabled() {
		return c.getDynamicAccess(user, pass)
	}

	return nil, ErrUnknownUser
}

func (c *Config) getDynamicAccess(user string, password string) (*confpar.Access, error) {
	tenant, err := c.authTenant(user, password)
	if err != nil {
		return nil, err
	}
	return &confpar.Access{
		User: user,
		Pass: password,
		Fs:   "s3",
		Params: map[string]string{
			"bucket":    c.dynamicContentS3Bucket,
			"base_path": fmt.Sprintf("%s/%s/", c.dynamicContentS3Root, tenant),
		},
	}, nil
	return nil, ErrUnknownUser
}

func (c *Config) authTenant(user string, password string) (int64, error) {
	// obtain the tenant id from the token
	accessToken, err := c.authUserToAccessToken(user, password)
	if err != nil {
		return 0, err
	}
	tenant, err := c.authAccessTokenToTenant(accessToken)
	if err != nil {
		return 0, err
	} else {
		return tenant, nil
	}
}

func (c *Config) authAccessTokenToTenant(token string) (int64, error) {
	return 0, nil
}

func (c *Config) authUserToAccessToken(user string, password string) (string, error) {
	type tokenRequest struct {
		GrantType string `json:"grant_type"`
		Username  string `json:"username"`
		Password  string `json:"password"`
	}

	type tokenResponse struct {
		AccessToken string `json:"access_token"`
	}

	if user == "" || password == "" {
		return "", ErrUnknownUser
	}
	tokenRequestPayload := tokenRequest{
		GrantType: "password",
		Username:  user,
		Password:  password,
	}
	marshalled, err := json.Marshal(tokenRequestPayload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.dynamicContentAuthUrl, bytes.NewReader(marshalled))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := http.Client{Timeout: 10 * time.Second}
	// send the request
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	// we do not forget to close the body to free resources
	// defer will execute that at the end of the current function
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	tokenResponsePayload := tokenResponse{}
	json.Unmarshal(resBody, &tokenResponsePayload)
	if tokenResponsePayload.AccessToken == "" {
		return "", ErrUnknownUser
	}
	return tokenResponsePayload.AccessToken, nil
}

func (c *Config) isDynamicContentEnabled() bool {
	return c.dynamicContentAuthUrl != "" && c.dynamicContentS3Bucket != ""
}
