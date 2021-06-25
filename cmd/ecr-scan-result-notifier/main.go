package main

import (
	"ecr-scan-result-notifier/internal/awsmod"
	"ecr-scan-result-notifier/internal/slack"
	"strings"

	//"../../internal/awsmod"
	//"../../internal/slack"
	"context"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"log"
	"net/http"
	"os"
	"strconv"
)

var encryptedChannel string = os.Getenv("CHANNEL")
var encryptedUserName string = os.Getenv("USERNAME")
var encryptedWebHookURL string = os.Getenv("WEBHOOKURL")
var exclude string = os.Getenv("EXCLUDE")
var kmsARN string = os.Getenv("KMS_ARN")
var decryptedChannel string
var decryptedUserName string
var decryptedWebHookURL string

func HandleRequest(ctx context.Context, event awsmod.SimpleType) (events.APIGatewayProxyResponse, error) {

	decryptedWebHookURL = string(awsmod.AwsKmsDecrypt(encryptedWebHookURL, kmsARN).Plaintext[:])
	decryptedUserName = string(awsmod.AwsKmsDecrypt(encryptedUserName, kmsARN).Plaintext[:])
	decryptedChannel = string(awsmod.AwsKmsDecrypt(encryptedChannel, kmsARN).Plaintext[:])

	sc := slack.SlackClient{
		WebHookUrl: decryptedWebHookURL,
		UserName:   decryptedUserName,
		Channel:    decryptedChannel,
	}

	//log.Print(fmt.Sprintf("decryptedWebHookURL:[%s] ", decryptedWebHookURL))
	//log.Print(fmt.Sprintf("decryptedUserName:[%s] ", decryptedUserName))
	//log.Print(fmt.Sprintf("decryptedChannel:[%s] ", decryptedChannel))

	c := event.Detail.FindingSeverityCounts.Critical
	h := event.Detail.FindingSeverityCounts.High
	m := event.Detail.FindingSeverityCounts.Medium
	l := event.Detail.FindingSeverityCounts.Low
	i := event.Detail.FindingSeverityCounts.Informational
	u := event.Detail.FindingSeverityCounts.Undefined

	//log.Print(fmt.Sprintf("Critical:[%d] ", c))
	//log.Print(fmt.Sprintf("High:[%d] ", h))
	//log.Print(fmt.Sprintf("Medium:[%d] ", m))

	detail := "CRITICAL: " + strconv.FormatInt(c, 10) +
		"\n" + "HIGH: " + strconv.FormatInt(h, 10) +
		"\n" + "MEDIUM:" + strconv.FormatInt(m, 10) +
		"\n" + "LOW:" + strconv.FormatInt(l, 10) +
		"\n" + "INFORMATIONAL" + strconv.FormatInt(i, 10) +
		"\n" + "UNDEFINED:" + strconv.FormatInt(u, 10)

	var color string
	if h == 0 && m == 0 && c == 0 {
		color = "good"
	} else if h > 0 || c > 0 {
		color = "danger"
	} else if c == 0 && h == 0 && m > 0 {
		color = "warning"
	}

	//To send a notification with status (slack attachments)
	sr := slack.SlackJobNotification{
		Color:     color,
		IconEmoji: ":hammer_and_wrench",
		Details:   detail,
		Text:      "Amazon ECR Image Scan Findings Description",
		Title:     event.Detail.RepositoryName + ":" + event.Detail.ImageTags[0],
		TitleLink: "https://console.aws.amazon.com/ecr/repositories/" + event.Detail.RepositoryName + "/image/" + event.Detail.ImageDigest + "/scan-results/?region=ap-southeast-1",
	}

	// Contains returns false here.
	if !strings.Contains(event.Detail.RepositoryName, exclude) {
		err := sc.SendJobNotification(sr)
		if err != nil {
			log.Fatal(err)
		}
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       "OK",
	}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
