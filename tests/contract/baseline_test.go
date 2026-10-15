package contract

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// TestSmallProductionBaseline: the minimum deployment is the server, the
// worker and PostgreSQL (DEP-001, ADR 0001 and 0005). No Go dependency pulls
// in a cache, message broker or object store client. The production Compose
// file runs only ProudAuth processes next to the operator's PostgreSQL; the
// development one adds PostgreSQL and two development tools, nothing else.
func TestSmallProductionBaseline(t *testing.T) {
	gomod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"github.com/redis/", "github.com/go-redis/", "github.com/gomodule/redigo", "github.com/bradfitz/gomemcache",
		"github.com/segmentio/kafka-go", "github.com/IBM/sarama", "github.com/Shopify/sarama", "github.com/confluentinc/",
		"github.com/nats-io/", "github.com/rabbitmq/", "github.com/streadway/amqp", "cloud.google.com/go/pubsub",
		"github.com/aws/aws-sdk-go", "github.com/minio/", "cloud.google.com/go/storage", "github.com/Azure/azure-sdk-for-go",
		"go.etcd.io/etcd", "github.com/hashicorp/consul",
	} {
		if strings.Contains(string(gomod), forbidden) {
			t.Errorf("go.mod requires %s: the baseline must not need a cache, broker or object store", forbidden)
		}
	}
	proudauth := []string{"migrate", "realm", "server", "worker"}
	for _, stack := range []struct {
		file    string
		allowed []string
	}{
		{"deploy/prod/docker-compose.yaml", proudauth},
		{"deploy/dev/docker-compose.yaml", append([]string{"postgres", "mailpit", "swagger"}, proudauth...)},
	} {
		services, _ := deployDocs(t, stack.file)[0]["services"].(map[string]any)
		if len(services) == 0 {
			t.Fatalf("no services found in %s", stack.file)
		}
		for name := range services {
			if !slices.Contains(stack.allowed, name) {
				t.Errorf("%s runs %q; the baseline is %v", stack.file, name, stack.allowed)
			}
		}
	}
}
