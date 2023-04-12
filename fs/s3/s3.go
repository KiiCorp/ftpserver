// Package s3 provides an AWS S3 access layer
package s3

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	s3 "github.com/fclairamb/afero-s3"
	"github.com/fclairamb/ftpserver/fs/stripprefix"
	"github.com/spf13/afero"
	"os"
	"strconv"

	"github.com/fclairamb/ftpserver/config/confpar"
)

// LoadFs loads a file system from an access description
func LoadFs(access *confpar.Access) (afero.Fs, error) {
	endpoint := access.Params["endpoint"]
	region := access.Params["region"]
	bucket := access.Params["bucket"]
	keyID := access.Params["access_key_id"]
	secretAccessKey := access.Params["secret_access_key"]
	basePath := access.Params["base_path"]
	strip := access.Params["strip"]

	if region == "" {
		region = os.Getenv("AWS_REGION")
		if region == "" {
			return nil, errors.New("region is required")
		}
	}

	conf := aws.Config{
		Region:           aws.String(region),
		DisableSSL:       aws.Bool(access.Params["disable_ssl"] == "true"),
		S3ForcePathStyle: aws.Bool(access.Params["path_style"] == "true"),
	}

	if keyID != "" && secretAccessKey != "" {
		conf.Credentials = credentials.NewStaticCredentials(keyID, secretAccessKey, "")
	}

	if endpoint != "" {
		conf.Endpoint = aws.String(endpoint)
	}

	sess, errSession := session.NewSession(&conf)

	if errSession != nil {
		return nil, errSession
	}
	s3Fs := s3.NewFs(bucket, sess)

	var fs afero.Fs
	fs = s3Fs
	if strip != "" {
		n, err := strconv.Atoi(strip)
		if err != nil {
			return nil, errors.New("Error while converting 'strip' value " + strip + " to a number: " + err.Error())
		}
		fs = stripprefix.NewStripPrefixFs(fs, n)
	}
	if basePath != "" {
		fs = afero.NewBasePathFs(fs, basePath)
	}
	return fs, nil

}
