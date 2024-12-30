FROM ubuntu:latest

# Set the Go version argument (updated to 1.21.3)
ARG GO_VERSION=1.21.3
ENV GO_VERSION=${GO_VERSION}

# Update package list and install necessary dependencies
RUN apt-get update && apt-get install -y wget git gcc ca-certificates

# Download and install Go from the specific version URL
RUN wget -P /tmp "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"

# Extract Go and remove the tarball to clean up
RUN tar -C /usr/local -xzf "/tmp/go${GO_VERSION}.linux-amd64.tar.gz" && rm "/tmp/go${GO_VERSION}.linux-amd64.tar.gz"

# Set Go environment variables
ENV PATH /usr/local/go/bin:$PATH

# Install Reflex to watch files and rebuild on change
RUN go install github.com/cespare/reflex@latest

# Ensure reflex is in the PATH
ENV PATH /root/go/bin:$PATH

# Create the Go workspace and copy the source code into the container
WORKDIR /app
COPY . .

# Ensure go.mod uses a valid Go version (this step ensures that the version in the container is correct)
RUN sed -i 's/go 1.22.3/go 1.21.3/' go.mod

# Download Go dependencies (this will use the go.mod in the root of the project)
RUN go mod tidy

# Build the Go application
RUN go build -ldflags="-s -w" -o reaper ./cmd/reaper

# Command to run the file watcher with Reflex
CMD /root/go/bin/reflex -r '\.go$' -s -- sh -c "go build -o reaper ./cmd/reaper && ./reaper"
