package mirror

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/regclient/regclient/types/ref"
)

func runHook(ctx context.Context, logger *slog.Logger, hook *config.Hook, kind string, src, tgt ref.Ref) error {
	if hook == nil || hook.Type == "" {
		return nil
	}
	if hook.Type != "script" {
		return fmt.Errorf("unsupported hook type %q", hook.Type)
	}
	if len(hook.Params) == 0 {
		return fmt.Errorf("hook %s has no command", kind)
	}
	cmd := exec.CommandContext(ctx, hook.Params[0], hook.Params[1:]...)
	cmd.Env = append(os.Environ(),
		"REGSYNC_HOOK="+kind,
		"REGSYNC_SRC="+src.CommonName(),
		"REGSYNC_TGT="+tgt.CommonName(),
	)
	logger.Debug("running hook", "type", kind, "params", hook.Params)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hook %s: %w: %s", kind, err, out)
	}
	return nil
}
