package redis

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/cchulo/project-juggernaut/internal/core/contracts/contracttest"
)

func TestContract(t *testing.T) {
	mr := miniredis.RunT(t)
	s := &Store{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()}), prefix: "jg:"}
	contracttest.UserSecretStore(t, s)
}
