package awsmod

import (
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"os"
)

// Lambda Environment Variables
var functionName string = os.Getenv("AWS_LAMBDA_FUNCTION_NAME")

type SimpleType struct {
	Version    string     `json:"version"`
	ID         string     `json:"id"`
	DetailType string     `json:"detail-type"`
	Source     string     `json:"source"`
	Time       string     `json:"time"`
	Region     string     `json:"region"`
	Resources  []string   `json:"resources"`
	Account    string     `json:"account"`
	Detail     DetailType `json:"detail"`
}

type DetailType struct {
	ScanStatus            string                    `json:"scan-status"`
	RepositoryName        string                    `json:"repository-name"`
	FindingSeverityCounts FindingSeverityCountsType `json:"finding-severity-counts"`
	ImageDigest           string                    `json:"image-digest"`
	ImageTags             []string                  `json:"image-tags"`
}

type FindingSeverityCountsType struct {
	Critical      int64 `json:"CRITICAL"`
	High          int64 `json:"HIGH"`
	Medium        int64 `json:"MEDIUM"`
	Low           int64 `json:"LOW"`
	Informational int64 `json:"INFORMATIONAL"`
	Undefined     int64 `json:"UNDEFINED"`
}

func AwsKmsDecrypt(a string, b string) *kms.DecryptOutput {
	svc := kms.New(session.Must(session.NewSession()), aws.NewConfig().WithRegion("ap-southeast-1"))

	decodedBytes, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		panic(err)
	}

	input := &kms.DecryptInput{
		CiphertextBlob: decodedBytes,
		EncryptionContext: aws.StringMap(map[string]string{
			"LambdaFunctionName": functionName,
		}),
		KeyId: aws.String(b),
	}

	result, err := svc.Decrypt(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeNotFoundException:
				fmt.Println(kms.ErrCodeNotFoundException, aerr.Error())
			case kms.ErrCodeDisabledException:
				fmt.Println(kms.ErrCodeDisabledException, aerr.Error())
			case kms.ErrCodeInvalidCiphertextException:
				fmt.Println(kms.ErrCodeInvalidCiphertextException, aerr.Error())
			case kms.ErrCodeKeyUnavailableException:
				fmt.Println(kms.ErrCodeKeyUnavailableException, aerr.Error())
			case kms.ErrCodeIncorrectKeyException:
				fmt.Println(kms.ErrCodeIncorrectKeyException, aerr.Error())
			case kms.ErrCodeInvalidKeyUsageException:
				fmt.Println(kms.ErrCodeInvalidKeyUsageException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInvalidGrantTokenException:
				fmt.Println(kms.ErrCodeInvalidGrantTokenException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeInvalidStateException:
				fmt.Println(kms.ErrCodeInvalidStateException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		//return
	}

	return result
}
