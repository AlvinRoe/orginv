package githubclient

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	gogithub "github.com/google/go-github/v82/github"
	"golang.org/x/oauth2"
)

type retryRoundTripper struct {
	transport  http.RoundTripper
	maxRetries int
	baseDelay  time.Duration
}

type Options struct {
	MaxRetries      int
	BaseDelay       time.Duration
	RepoPageWorkers int
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		resp, err = r.transport.RoundTrip(req)
		if err != nil {
			if attempt < r.maxRetries {
				if sleepErr := sleepWithContext(req.Context(), r.baseDelay*time.Duration(1<<attempt)); sleepErr != nil {
					return nil, sleepErr
				}
				continue
			}
			return nil, err
		}

		if isRateLimitResponse(resp) {
			// Let go-github return a rate-limit error immediately; do not wait/retry.
			return resp, nil
		}

		if retryableStatus(resp) {
			if attempt < r.maxRetries {
				resp.Body.Close()
				delay := retryDelay(r.baseDelay, attempt)
				log.Printf("Retrying request (attempt %d/%d) after %v: %s %s status=%d", attempt+1, r.maxRetries, delay, req.Method, req.URL, resp.StatusCode)
				if sleepErr := sleepWithContext(req.Context(), delay); sleepErr != nil {
					return nil, sleepErr
				}
				continue
			}
		}

		return resp, nil
	}

	return resp, err
}

type Client struct {
	raw             *gogithub.Client
	repoPageWorkers int
}

func New(ctx context.Context, token string, opts Options) *Client {
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 5
	}
	if opts.BaseDelay <= 0 {
		opts.BaseDelay = 1 * time.Second
	}
	if opts.RepoPageWorkers <= 0 {
		opts.RepoPageWorkers = 4
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauthClient := oauth2.NewClient(ctx, ts)
	retryClient := &http.Client{
		Transport: &retryRoundTripper{
			transport:  oauthClient.Transport,
			maxRetries: opts.MaxRetries,
			baseDelay:  opts.BaseDelay,
		},
		Timeout: oauthClient.Timeout,
	}
	return &Client{
		raw:             gogithub.NewClient(retryClient),
		repoPageWorkers: opts.RepoPageWorkers,
	}
}

func (c *Client) FetchAllRepos(ctx context.Context, org string, perPage int) ([]*gogithub.Repository, error) {
	opt := &gogithub.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: gogithub.ListOptions{PerPage: perPage, Page: 1},
	}
	firstPageRepos, resp, err := c.raw.Repositories.ListByOrg(ctx, org, opt)
	if err != nil {
		return nil, err
	}

	allRepos := make([]*gogithub.Repository, 0, len(firstPageRepos))
	allRepos = append(allRepos, firstPageRepos...)
	if resp.LastPage <= 1 {
		return allRepos, nil
	}

	var mu sync.Mutex
	var errMu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	sem := make(chan struct{}, c.repoPageWorkers)
	for page := 2; page <= resp.LastPage; page++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(pageNum int) {
			defer wg.Done()
			defer func() { <-sem }()
			pageOpt := &gogithub.RepositoryListByOrgOptions{
				Type:        "all",
				ListOptions: gogithub.ListOptions{PerPage: perPage, Page: pageNum},
			}
			repos, _, pErr := c.raw.Repositories.ListByOrg(ctx, org, pageOpt)
			if pErr != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("list repos page %d failed: %w", pageNum, pErr)
				}
				errMu.Unlock()
				return
			}
			mu.Lock()
			allRepos = append(allRepos, repos...)
			mu.Unlock()
		}(page)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return allRepos, nil
}

func (c *Client) FetchSBOM(ctx context.Context, org, repoName string) (*gogithub.SBOM, error) {
	sbom, _, err := c.raw.DependencyGraph.GetSBOM(ctx, org, repoName)
	return sbom, err
}

func (c *Client) FetchDependabotAlerts(ctx context.Context, org string, perPage int) ([]*gogithub.DependabotAlert, int, error) {
	all := make([]*gogithub.DependabotAlert, 0)
	pageCount := 0
	seen := make(map[string]struct{})
	states := []string{"open", "dismissed", "fixed", "auto_dismissed"}
	for _, state := range states {
		after := ""
		for {
			opts := &gogithub.ListAlertsOptions{
				State: stringPtr(state),
				ListCursorOptions: gogithub.ListCursorOptions{
					PerPage: perPage,
					After:   after,
				},
			}
			alerts, resp, err := c.raw.Dependabot.ListOrgAlerts(ctx, org, opts)
			if err != nil {
				return nil, pageCount, fmt.Errorf("dependabot org alerts fetch failed (org=%s state=%s after=%q): %w", org, state, after, err)
			}
			pageCount++
			added := 0
			for _, alert := range alerts {
				if alert == nil {
					continue
				}
				key := dependabotAlertKey(alert)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				all = append(all, alert)
				added++
			}
			log.Printf("dependabot page fetched: state=%s after=%q items=%d added=%d total=%d", state, after, len(alerts), added, len(all))
			if resp.After == "" {
				break
			}
			after = resp.After
		}
	}
	return all, pageCount, nil
}

func (c *Client) FetchCodeScanningAlerts(ctx context.Context, org string, perPage int) ([]*gogithub.Alert, int, error) {
	all := make([]*gogithub.Alert, 0)
	pageCount := 0
	seen := make(map[string]struct{})
	states := []string{"open", "closed"}
	for _, state := range states {
		page := 1
		for {
			opts := &gogithub.AlertListOptions{
				State:       state,
				ListOptions: gogithub.ListOptions{PerPage: perPage, Page: page},
			}
			alerts, resp, err := c.raw.CodeScanning.ListAlertsForOrg(ctx, org, opts)
			if err != nil {
				return nil, pageCount, fmt.Errorf("code scanning org alerts fetch failed (org=%s state=%s page=%d): %w", org, state, page, err)
			}
			pageCount++
			added := 0
			for _, alert := range alerts {
				if alert == nil {
					continue
				}
				key := codeScanningAlertKey(alert)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				all = append(all, alert)
				added++
			}
			log.Printf("code scanning page fetched: state=%s page=%d items=%d added=%d total=%d", state, page, len(alerts), added, len(all))
			if resp.NextPage == 0 {
				break
			}
			page = resp.NextPage
		}
	}
	return all, pageCount, nil
}

func (c *Client) FetchSecretScanningAlerts(ctx context.Context, org string, perPage int) ([]*gogithub.SecretScanningAlert, int, error) {
	all := make([]*gogithub.SecretScanningAlert, 0)
	pageCount := 0
	seen := make(map[string]struct{})
	states := []string{"open", "resolved"}
	for _, state := range states {
		page := 1
		for {
			opts := &gogithub.SecretScanningAlertListOptions{
				State:       state,
				ListOptions: gogithub.ListOptions{PerPage: perPage, Page: page},
			}
			alerts, resp, err := c.raw.SecretScanning.ListAlertsForOrg(ctx, org, opts)
			if err != nil {
				return nil, pageCount, fmt.Errorf("secret scanning org alerts fetch failed (org=%s state=%s page=%d): %w", org, state, page, err)
			}
			pageCount++
			added := 0
			for _, alert := range alerts {
				if alert == nil {
					continue
				}
				key := secretScanningAlertKey(alert)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				all = append(all, alert)
				added++
			}
			log.Printf("secret scanning page fetched: state=%s page=%d items=%d added=%d total=%d", state, page, len(alerts), added, len(all))
			if resp.NextPage == 0 {
				break
			}
			page = resp.NextPage
		}
	}
	return all, pageCount, nil
}

func stringPtr(v string) *string {
	return &v
}

func dependabotAlertKey(a *gogithub.DependabotAlert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	return firstNonEmpty(a.GetHTMLURL(), a.GetURL(), fmt.Sprintf("unknown:%d", a.GetNumber()))
}

func codeScanningAlertKey(a *gogithub.Alert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	if a.GetHTMLURL() != "" {
		return a.GetHTMLURL()
	}
	return fmt.Sprintf("unknown:%d", a.GetNumber())
}

func secretScanningAlertKey(a *gogithub.SecretScanningAlert) string {
	if a == nil {
		return ""
	}
	repo := a.GetRepository()
	if repo != nil && repo.GetID() != 0 {
		return fmt.Sprintf("%d:%d", repo.GetID(), a.GetNumber())
	}
	if a.GetHTMLURL() != "" {
		return a.GetHTMLURL()
	}
	return fmt.Sprintf("unknown:%d", a.GetNumber())
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func retryableStatus(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return resp.StatusCode >= 500
}

func isRateLimitResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode != http.StatusForbidden {
		return false
	}
	if resp.Header.Get("Retry-After") != "" {
		return true
	}
	return resp.Header.Get("X-RateLimit-Remaining") == "0"
}

func retryDelay(baseDelay time.Duration, attempt int) time.Duration {
	delay := baseDelay * time.Duration(1<<attempt)
	return delay
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
