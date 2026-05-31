package remnawave

import (
	"context"
	"fmt"
	"log"
	"time"
)

// GetUsers fetches all users from Remnawave with pagination.
//
// Hardened against the panel's intermittent "A024 / Get all users error" 500s
// on deep offsets: each page is retried with backoff, and a page that still
// fails after retries is skipped (logged) rather than aborting the whole sweep
// — a single bad page no longer leaves remna_users empty. The loop is bounded
// by the reported total, and paces between pages to avoid hammering the API.
func (c *Client) GetUsers(ctx context.Context) (*UsersResponse, error) {
	const (
		pageSize  = 1000
		pagePause = 200 * time.Millisecond

		// Per-page retry tuning. The panel intermittently returns 500/A024
		// ("Get all users error") on deep offsets; instead of giving up after
		// a fixed number of tries we keep retrying with exponential backoff
		// until the total retry budget for that page is spent.
		retryInitialBackoff = 1 * time.Second
		retryMaxBackoff     = 30 * time.Second
		retryBudget         = 5 * time.Minute
	)

	var allUsers []User
	total := -1
	start := 0

	for {
		if total >= 0 && start >= total {
			break
		}

		var resp *UsersResponse
		var lastErr error
		deadline := time.Now().Add(retryBudget)
		backoff := retryInitialBackoff
		for attempt := 1; ; attempt++ {
			endpoint := fmt.Sprintf("/api/users?start=%d&size=%d", start, pageSize)
			data, err := c.doRequest(ctx, "GET", endpoint, nil)
			if err == nil {
				resp, lastErr = parseResponse[*UsersResponse](data)
				if lastErr == nil {
					break
				}
			} else {
				lastErr = err
			}

			// Stop if the next wait would push us past the retry budget.
			now := time.Now()
			if !now.Add(backoff).Before(deadline) {
				break
			}

			log.Printf("[remnawave] users page start=%d attempt %d failed: %v, retrying in %v (budget %v left)",
				start, attempt, lastErr, backoff, deadline.Sub(now).Round(time.Second))

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}

			// Exponential growth, capped.
			backoff *= 2
			if backoff > retryMaxBackoff {
				backoff = retryMaxBackoff
			}
		}

		if lastErr != nil {
			// Can't continue without a total to bound the loop — fail hard only
			// if even the first page is unreachable.
			if total < 0 {
				return nil, fmt.Errorf("users first page failed: %w", lastErr)
			}
			log.Printf("[remnawave] users page start=%d giving up after retry budget %v, skipping: %v",
				start, retryBudget, lastErr)
			start += pageSize
			continue
		}

		if total < 0 {
			total = resp.Total
		}
		allUsers = append(allUsers, resp.Users...)

		// Short page = reached the end (only trustworthy when total is unknown).
		if len(resp.Users) < pageSize {
			break
		}

		start += pageSize
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pagePause):
		}
	}

	return &UsersResponse{Users: allUsers, Total: total}, nil
}

// GetUserByUUID fetches a specific user by UUID
func (c *Client) GetUserByUUID(ctx context.Context, uuid string) (*User, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/%s", uuid), nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*User](data)
}

// GetUserByEmail fetches users by email
func (c *Client) GetUserByEmail(ctx context.Context, email string) ([]User, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/by-email/%s", email), nil)
	if err != nil {
		return nil, err
	}
	resp, err := parseResponse[*UsersResponse](data)
	if err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// GetUserByUsername fetches a user by username
func (c *Client) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/by-username/%s", username), nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*User](data)
}

// GetUserByID fetches a user by numeric ID (the ID used in xray logs)
func (c *Client) GetUserByID(ctx context.Context, id string) (*User, error) {
	data, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/users/by-id/%s", id), nil)
	if err != nil {
		return nil, err
	}
	return parseResponse[*User](data)
}

// DisableUser disables a user on the Remnawave panel (status → DISABLED).
// The exact path tracks the Remnawave panel API; adjust if the panel version
// differs. Uses doRequestStatus since the panel may answer 200/201.
func (c *Client) DisableUser(ctx context.Context, uuid string) error {
	endpoint := fmt.Sprintf("/api/users/%s/actions/disable", uuid)
	data, err := c.doRequestStatus(ctx, "POST", endpoint, nil)
	if err != nil {
		log.Printf("[remnawave-client] DISABLE user %s - error: %v", uuid, err)
		return err
	}
	log.Printf("[remnawave-client] DISABLE user %s - ok: %s", uuid, string(data))
	return nil
}

// DeleteUser permanently deletes a user on the Remnawave panel.
func (c *Client) DeleteUser(ctx context.Context, uuid string) error {
	endpoint := fmt.Sprintf("/api/users/%s", uuid)
	data, err := c.doRequestStatus(ctx, "DELETE", endpoint, nil)
	if err != nil {
		log.Printf("[remnawave-client] DELETE user %s - error: %v", uuid, err)
		return err
	}
	log.Printf("[remnawave-client] DELETE user %s - ok: %s", uuid, string(data))
	return nil
}
