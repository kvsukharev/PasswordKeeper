package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/kvsuharev/passwordkeeper/api/gen"
	"github.com/kvsuharev/passwordkeeper/internal/client/config"
	grpcclient "github.com/kvsuharev/passwordkeeper/internal/client/grpc"
	"github.com/kvsuharev/passwordkeeper/internal/client/storage"
)

func newSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Synchronise local cache with the server",
		RunE:  runSync,
	}
}

func runSync(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	db, err := storage.OpenDB(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := cmd.Context()
	sessionStore := storage.NewSessionStore(db)
	sess, err := sessionStore.Load(ctx)
	if err != nil {
		return err
	}

	pendingStore := storage.NewPendingStore(db)
	secrets := storage.NewSecretStore(db)

	conn, err := grpcclient.Dial(cfg.ServerAddr, cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer conn.Close()

	if refreshErr := refreshSessionIfNeeded(ctx, conn, sessionStore, sess); refreshErr != nil {
		return refreshErr
	}

	authCtx := grpcclient.AuthCtx(ctx, sess.AccessToken)

	// --- Push pending changes ---
	pending, err := pendingStore.List(ctx)
	if err != nil {
		return fmt.Errorf("load pending changes: %w", err)
	}

	conflictIDs := make(map[string]struct{})

	if len(pending) > 0 {
		changes := make([]*pb.SecretChange, 0, len(pending))
		for _, p := range pending {
			changes = append(changes, &pb.SecretChange{
				Action:      pendingActionToPb(p.Action),
				Id:          p.ID,
				Type:        modelSecretTypeToPb(p.Type),
				Name:        p.Name,
				Payload:     p.Payload,
				BaseVersion: p.BaseVersion,
			})
		}

		pushResp, pushErr := conn.Sync.Push(authCtx, &pb.PushRequest{Changes: changes})
		if pushErr != nil {
			return fmt.Errorf("push changes: %w", pushErr)
		}

		// Update local versions for successfully applied changes.
		for _, r := range pushResp.GetResults() {
			sec, getErr := secrets.GetByID(ctx, r.GetId())
			if getErr != nil {
				continue
			}
			sec.Version = r.GetNewVersion()
			_ = secrets.Upsert(ctx, sec)
		}

		// Record conflict IDs; update local cache with server version + conflict flag.
		for _, c := range pushResp.GetConflicts() {
			conflictIDs[c.GetId()] = struct{}{}
			if c.GetServerSecret() != nil {
				ls := localSecretFromPb(c.GetServerSecret())
				ls.IsConflict = true
				_ = secrets.Upsert(ctx, ls)
			}
		}

		if clearErr := pendingStore.Clear(ctx); clearErr != nil {
			return fmt.Errorf("clear pending changes: %w", clearErr)
		}

		fmt.Printf("Pushed %d change(s)", len(pushResp.GetResults()))
		if n := len(pushResp.GetConflicts()); n > 0 {
			fmt.Printf(", %d conflict(s)", n)
		}
		fmt.Println()
	}

	// --- Pull changes ---
	sinceVersion, err := sessionStore.GetSyncVersion(ctx)
	if err != nil {
		return fmt.Errorf("get sync version: %w", err)
	}

	pullResp, err := conn.Sync.Pull(authCtx, &pb.PullRequest{SinceVersion: sinceVersion})
	if err != nil {
		return fmt.Errorf("pull changes: %w", err)
	}

	seenInPull := make(map[string]struct{}, len(conflictIDs))
	var conflictNames []string

	for _, s := range pullResp.GetSecrets() {
		ls := localSecretFromPb(s)
		// Preserve the conflict flag for secrets that had push conflicts.
		if _, isConflict := conflictIDs[ls.ID]; isConflict {
			ls.IsConflict = true
			seenInPull[ls.ID] = struct{}{}
			conflictNames = append(conflictNames, ls.Name)
		}
		if upsertErr := secrets.Upsert(ctx, ls); upsertErr != nil {
			return fmt.Errorf("cache pulled secret: %w", upsertErr)
		}
	}

	// Collect names for conflicts not included in the pull response.
	for id := range conflictIDs {
		if _, seen := seenInPull[id]; seen {
			continue
		}
		sec, getErr := secrets.GetByID(ctx, id)
		if getErr == nil {
			conflictNames = append(conflictNames, sec.Name)
		} else {
			conflictNames = append(conflictNames, id)
		}
	}

	if setErr := sessionStore.SetSyncVersion(ctx, pullResp.GetCurrentVersion()); setErr != nil {
		return fmt.Errorf("update sync version: %w", setErr)
	}

	fmt.Printf("Pulled %d update(s). Local cache is at version %d.\n",
		len(pullResp.GetSecrets()), pullResp.GetCurrentVersion())

	if len(conflictNames) > 0 {
		fmt.Printf("\nConflicts detected for: %s\n", joinQuoted(conflictNames))
		fmt.Println("Use 'edit' to resolve. Conflicted secrets are marked [!] in 'list'.")
	}

	return nil
}

func joinQuoted(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(quoted, ", ")
}
