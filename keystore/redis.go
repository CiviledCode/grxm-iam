package keystore

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store defines the interface for interacting with the fast, in-memory keystore
// primarily used for tracking banned/invalidated active tokens.
type Store interface {
	// BanUser adds a user's ID to the keystore for the duration of the TTL.
	// This acts as a denylist that consumer APIs can quickly check.
	BanUser(ctx context.Context, userID string, ttl time.Duration) error
	// UnbanUser removes a user's ID from the keystore, unblocking their active tokens.
	UnbanUser(ctx context.Context, userID string) error
	// IsBanned checks if a user is currently in the denylist.
	IsBanned(ctx context.Context, userID string) (bool, error)
	// Ping checks if the keystore is reachable.
	Ping(ctx context.Context) error
	// Close closes the connection to the keystore.
	Close() error
}

// RedisStore is a Redis implementation of the Store interface.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a new RedisStore instance connected to the specified Redis server.
func NewRedisStore(host string, port int, password string, db int) *RedisStore {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password, // no password set
		DB:       db,       // use default DB
	})

	return &RedisStore{
		client: rdb,
	}
}

// banKey generates the Redis key for a banned user.
func banKey(userID string) string {
	return fmt.Sprintf("banned:user:%s", userID)
}

func (r *RedisStore) BanUser(ctx context.Context, userID string, ttl time.Duration) error {
	// The value "1" is arbitrary; we just need the key to exist with a TTL.
	return r.client.Set(ctx, banKey(userID), "1", ttl).Err()
}

func (r *RedisStore) UnbanUser(ctx context.Context, userID string) error {
	return r.client.Del(ctx, banKey(userID)).Err()
}

func (r *RedisStore) IsBanned(ctx context.Context, userID string) (bool, error) {
	err := r.client.Get(ctx, banKey(userID)).Err()
	if err == redis.Nil {
		return false, nil // Key does not exist, user is not banned
	} else if err != nil {
		return false, err // An actual error occurred
	}
	return true, nil // Key exists, user is banned
}

func (r *RedisStore) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *RedisStore) Close() error {
	return r.client.Close()
}
