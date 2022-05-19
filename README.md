# ecr-scan-result-notifier

## Setting up go module

```bash
go mod init ecr-scan-result-notifier
```

## Build ecr-scan-result-notifier

```bash
cd cmd/ecr-scan-result-notifier
GOOS=linux CGO_ENABLED=0 go build main.go
```

## Zip before deploy to AWS Lambda

```bash
zip main.zip main
```
