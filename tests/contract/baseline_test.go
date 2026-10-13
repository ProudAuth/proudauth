package contract

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestSmallProductionBaseline: the minimum deployment is the server, the
// worker and PostgreSQL (DEP-001, ADR 0001 and 0005). No Go dependency pulls
// in a cache, message broker or object store client, and the Compose stack
// runs nothing else.
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
	compose, err := os.ReadFile("../../deploy/compose/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	services := regexp.MustCompile(`(?m)^  ([a-z][a-z0-9-]*):\s*$`).FindAllStringSubmatch(string(compose), -1)
	allowed := map[string]bool{"postgres": true, "migrate": true, "server": true, "worker": true}
	if len(services) == 0 {
		t.Fatal("no services found in deploy/compose/compose.yaml")
	}
	for _, s := range services {
		if !allowed[s[1]] {
			t.Errorf("the Compose stack runs %q; the baseline is PostgreSQL, the migration step, the server and the worker", s[1])
		}
	}
}
