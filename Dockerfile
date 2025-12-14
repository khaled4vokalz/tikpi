  FROM golang:1.24-alpine

  # Install libpcap
  RUN apk add --no-cache libpcap-dev gcc musl-dev

  WORKDIR /app

  # Copy go mod files
  COPY go.mod go.sum ./
  RUN go mod download

  # Copy source code
  COPY . .

  # Build
  RUN go build -o tikpi .

  # Run with network capabilities
  CMD ["./tikpi"]
