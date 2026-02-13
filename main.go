package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/go-github/v82/github"
	"golang.org/x/oauth2"
)

type retryRoundTripper struct {
	transport  http.RoundTripper
	maxRetries int
	baseDelay  time.Duration
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		// Clone the request body if needed for retries
		if req.Body != nil && attempt > 0 {
			// For retries, we need the request to be re-readable
			// This works because oauth2 transport handles this
		}

		resp, err = r.transport.RoundTrip(req)
		if err != nil {
			// Network error, retry
			if attempt < r.maxRetries {
				time.Sleep(r.baseDelay * time.Duration(1<<attempt)) // exponential backoff
				continue
			}
			return nil, err
		}

		// Retry on 5xx errors or 429 (rate limit)
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			if attempt < r.maxRetries {
				resp.Body.Close()
				delay := r.baseDelay * time.Duration(1<<attempt)
				// Check for Retry-After header
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if seconds, parseErr := strconv.Atoi(retryAfter); parseErr == nil {
						delay = time.Duration(seconds) * time.Second
					}
				}
				log.Printf("Retrying request (attempt %d/%d) after %v: %s %s", attempt+1, r.maxRetries, delay, req.Method, req.URL)
				time.Sleep(delay)
				continue
			}
		}

		return resp, nil
	}

	return resp, err
}

func main() {
	// use environment variables directly (no flags)
	org := os.Getenv("GITHUB_ORG")
	if org == "" {
		log.Fatal("GITHUB_ORG environment variable is not set")
	}

	perPage := 100 // max allowed by GitHub API
	if perEnv := os.Getenv("RESULTS_PER_PAGE"); perEnv != "" {
		pp, err := strconv.Atoi(perEnv)
		if err != nil || pp <= 0 {
			log.Fatalf("invalid RESULTS_PER_PAGE: %s", perEnv)
		}
		perPage = pp
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN environment variable is not set")
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauthClient := oauth2.NewClient(ctx, ts)

	// Wrap the oauth client's transport with retry logic
	retryClient := &http.Client{
		Transport: &retryRoundTripper{
			transport:  oauthClient.Transport,
			maxRetries: 3,
			baseDelay:  1 * time.Second,
		},
		Timeout: oauthClient.Timeout,
	}
	client := github.NewClient(retryClient)

	// TEMPORARY: Create sboms directory if it doesn't exist
	// This should be handled by proper setup/config in production
	if err := os.MkdirAll("./sboms", 0755); err != nil {
		log.Fatalf("failed to create sboms directory: %v", err)
	}

	// Fetch all repos across all pages concurrently
	var allRepos []*github.Repository
	var reposMu sync.Mutex

	// First request to determine total pages
	opt := &github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: github.ListOptions{
			PerPage: perPage,
			Page:    1,
		},
	}

	firstPageRepos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
	if err != nil {
		log.Fatalf("failed to list repos: %v", err)
	}
	allRepos = append(allRepos, firstPageRepos...)
	fmt.Printf("Fetched page 1, got %d repos\n", len(firstPageRepos))

	lastPage := resp.LastPage
	if lastPage > 1 {
		var pagesWg sync.WaitGroup
		// Fetch remaining pages concurrently
		for page := 2; page <= lastPage; page++ {
			pagesWg.Add(1)
			go func(pageNum int) {
				defer pagesWg.Done()
				pageOpt := &github.RepositoryListByOrgOptions{
					Type: "all",
					ListOptions: github.ListOptions{
						PerPage: perPage,
						Page:    pageNum,
					},
				}
				repos, _, err := client.Repositories.ListByOrg(ctx, org, pageOpt)
				if err != nil {
					log.Printf("failed to list repos page %d: %v", pageNum, err)
					return
				}
				reposMu.Lock()
				allRepos = append(allRepos, repos...)
				reposMu.Unlock()
				fmt.Printf("Fetched page %d, got %d repos\n", pageNum, len(repos))
			}(page)
		}
		pagesWg.Wait()
	}

	fmt.Printf("\nTotal repos found: %d\n", len(allRepos))

	// Filter out archived repos
	var activeRepos []*github.Repository
	for _, repo := range allRepos {
		if !repo.GetArchived() {
			activeRepos = append(activeRepos, repo)
		}
	}
	fmt.Printf("Active (non-archived) repos: %d\n", len(activeRepos))
	fmt.Println("Fetching SBOMs concurrently...")

	// Use goroutines with a worker pool to fetch SBOMs
	const numWorkers = 10
	repoChan := make(chan *github.Repository, len(activeRepos))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for repo := range repoChan {
				repoName := repo.GetName()
				sbom, _, err := client.DependencyGraph.GetSBOM(ctx, org, repoName)
				if err != nil {
					log.Printf("[worker %d] failed to get SBOM for %s: %v", workerID, repoName, err)
					continue
				}

				sbomJSON, err := json.MarshalIndent(sbom, "", "  ")
				if err != nil {
					log.Printf("[worker %d] failed to marshal SBOM for %s: %v", workerID, repoName, err)
					continue
				}

				filename := fmt.Sprintf("./sboms/%s.json", repoName)
				if err := os.WriteFile(filename, sbomJSON, 0644); err != nil {
					log.Printf("[worker %d] failed to write SBOM for %s: %v", workerID, repoName, err)
					continue
				}

				fmt.Printf("[worker %d] saved SBOM for %s\n", workerID, repoName)
			}
		}(i)
	}

	// Send repos to workers
	for _, repo := range activeRepos {
		repoChan <- repo
	}
	close(repoChan)

	// Wait for all workers to finish
	wg.Wait()
	fmt.Println("\nDone fetching all SBOMs!")
}
