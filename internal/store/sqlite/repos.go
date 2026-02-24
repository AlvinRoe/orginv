package sqlite

import (
	"database/sql"
	"strings"

	"github.com/google/go-github/v82/github"
)

func upsertRepo(db *sql.DB, org string, repo *github.Repository) error {
	topics := strings.Join(repo.Topics, ",")
	advancedSecurityStatus := ""
	secretScanningStatus := ""
	secretScanningPushProtectionStatus := ""
	dependabotSecurityUpdatesStatus := ""
	secretScanningValidityChecksStatus := ""
	if repo.SecurityAndAnalysis != nil {
		if repo.SecurityAndAnalysis.AdvancedSecurity != nil {
			advancedSecurityStatus = repo.SecurityAndAnalysis.AdvancedSecurity.GetStatus()
		}
		if repo.SecurityAndAnalysis.SecretScanning != nil {
			secretScanningStatus = repo.SecurityAndAnalysis.SecretScanning.GetStatus()
		}
		if repo.SecurityAndAnalysis.SecretScanningPushProtection != nil {
			secretScanningPushProtectionStatus = repo.SecurityAndAnalysis.SecretScanningPushProtection.GetStatus()
		}
		if repo.SecurityAndAnalysis.DependabotSecurityUpdates != nil {
			dependabotSecurityUpdatesStatus = repo.SecurityAndAnalysis.DependabotSecurityUpdates.GetStatus()
		}
		if repo.SecurityAndAnalysis.SecretScanningValidityChecks != nil {
			secretScanningValidityChecksStatus = repo.SecurityAndAnalysis.SecretScanningValidityChecks.GetStatus()
		}
	}

	_, err := db.Exec(`
		INSERT INTO repos(
			repo_id, name, full_name, visibility, private, archived, disabled,
			default_branch, language, open_issues_count, description, topics,
			size_kb, forks_count, stargazers_count, has_issues, has_projects, has_wiki, has_pages, has_discussions,
			is_fork, is_template, advanced_security_status,
			secret_scanning_status, secret_scanning_push_protection_status, dependabot_security_updates_status
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(repo_id) DO UPDATE SET
			name = excluded.name,
			full_name = excluded.full_name,
			visibility = excluded.visibility,
			private = excluded.private,
			archived = excluded.archived,
			disabled = excluded.disabled,
			default_branch = excluded.default_branch,
			language = excluded.language,
			open_issues_count = excluded.open_issues_count,
			description = excluded.description,
			topics = excluded.topics,
			size_kb = excluded.size_kb,
			forks_count = excluded.forks_count,
			stargazers_count = excluded.stargazers_count,
			has_issues = excluded.has_issues,
			has_projects = excluded.has_projects,
			has_wiki = excluded.has_wiki,
			has_pages = excluded.has_pages,
			has_discussions = excluded.has_discussions,
			is_fork = excluded.is_fork,
			is_template = excluded.is_template,
			advanced_security_status = excluded.advanced_security_status,
			secret_scanning_status = excluded.secret_scanning_status,
			secret_scanning_push_protection_status = excluded.secret_scanning_push_protection_status,
			dependabot_security_updates_status = excluded.dependabot_security_updates_status
	`,
		repo.GetID(),
		repo.GetName(),
		repo.GetFullName(),
		repo.GetVisibility(),
		boolToInt(repo.GetPrivate()),
		boolToInt(repo.GetArchived()),
		boolToInt(repo.GetDisabled()),
		repo.GetDefaultBranch(),
		repo.GetLanguage(),
		repo.GetOpenIssuesCount(),
		repo.GetDescription(),
		topics,
		repo.GetSize(),
		repo.GetForksCount(),
		repo.GetStargazersCount(),
		boolToInt(repo.GetHasIssues()),
		boolToInt(repo.GetHasProjects()),
		boolToInt(repo.GetHasWiki()),
		boolToInt(repo.GetHasPages()),
		boolToInt(repo.GetHasDiscussions()),
		boolToInt(repo.GetFork()),
		boolToInt(repo.GetIsTemplate()),
		advancedSecurityStatus,
		secretScanningStatus,
		secretScanningPushProtectionStatus,
		dependabotSecurityUpdatesStatus,
	)
	if err != nil {
		return err
	}

	immerseAskID, immerseJFrogProjectKey, immerseSASTCompliant, immerseSASTScanners := extractImmerseCustomProperties(repo.CustomProperties)

	_, err = db.Exec(`
		UPDATE repos
		SET
			node_id = ?, html_url = ?, clone_url = ?, git_url = ?, mirror_url = ?, ssh_url = ?, svn_url = ?,
			network_count = ?, subscribers_count = ?, watchers_count = ?, watchers = ?, auto_init = ?,
			allow_rebase_merge = ?, allow_update_branch = ?, allow_squash_merge = ?, allow_merge_commit = ?,
			allow_auto_merge = ?, allow_forking = ?, web_commit_signoff_required = ?, delete_branch_on_merge = ?,
			use_squash_pr_title_as_default = ?, has_downloads = ?,
			secret_scanning_validity_checks_status = ?, team_id = ?,
			immerse_ask_id = ?, immerse_jfrog_project_key = ?, immerse_sast_compliant = ?
		WHERE repo_id = ?
	`,
		repo.GetNodeID(), repo.GetHTMLURL(), repo.GetCloneURL(), repo.GetGitURL(), repo.GetMirrorURL(), repo.GetSSHURL(), repo.GetSVNURL(),
		repo.GetNetworkCount(), repo.GetSubscribersCount(), repo.GetWatchersCount(), repo.GetWatchers(), boolToInt(repo.GetAutoInit()),
		boolToInt(repo.GetAllowRebaseMerge()), boolToInt(repo.GetAllowUpdateBranch()), boolToInt(repo.GetAllowSquashMerge()), boolToInt(repo.GetAllowMergeCommit()),
		boolToInt(repo.GetAllowAutoMerge()), boolToInt(repo.GetAllowForking()), boolToInt(repo.GetWebCommitSignoffRequired()), boolToInt(repo.GetDeleteBranchOnMerge()),
		boolToInt(repo.GetUseSquashPRTitleAsDefault()), boolToInt(repo.GetHasDownloads()),
		secretScanningValidityChecksStatus, nullableInt64Value(repo.GetTeamID()),
		nullableString(immerseAskID), immerseJFrogProjectKey, immerseSASTCompliant,
		repo.GetID(),
	)
	if err != nil {
		return err
	}

	return upsertRepoScanners(db, repo.GetID(), immerseSASTScanners)
}
