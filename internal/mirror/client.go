package mirror

import (
	"fmt"
	"log/slog"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/regclient/regclient"
	rcconfig "github.com/regclient/regclient/config"
	"github.com/regclient/regclient/scheme/reg"
)

const userAgent = "suppline/mirror"

func newClient(cfg *config.RegsyncConfig, logger *slog.Logger) (*regclient.RegClient, error) {
	opts := []regclient.Opt{regclient.WithSlog(logger)}
	if cfg.Defaults.BlobLimit != 0 {
		opts = append(opts, regclient.WithRegOpts(reg.WithBlobLimit(cfg.Defaults.BlobLimit)))
	}
	if cfg.Defaults.CacheCount > 0 && cfg.Defaults.CacheTime != 0 {
		opts = append(opts, regclient.WithRegOpts(reg.WithCache(cfg.Defaults.CacheTime.Std(), cfg.Defaults.CacheCount)))
	}
	if !cfg.Defaults.SkipDockerConf {
		opts = append(opts, regclient.WithDockerCreds(), regclient.WithDockerCerts())
	}
	if cfg.Defaults.UserAgent != "" {
		opts = append(opts, regclient.WithUserAgent(cfg.Defaults.UserAgent))
	} else {
		opts = append(opts, regclient.WithUserAgent(userAgent))
	}

	hosts := make([]rcconfig.Host, 0, len(cfg.Creds))
	for _, cred := range cfg.Creds {
		host, err := credHost(cred)
		if err != nil {
			return nil, err
		}
		if host.Scheme != "" {
			logger.Warn("scheme is deprecated, for http set tls to disabled", "name", host.Name)
		}
		hosts = append(hosts, host)
	}
	if len(hosts) > 0 {
		opts = append(opts, regclient.WithConfigHost(hosts...))
	}
	return regclient.New(opts...), nil
}

func credHost(cred config.RegistryCredential) (rcconfig.Host, error) {
	host := rcconfig.Host{
		Name:          cred.Registry,
		Hostname:      cred.Hostname,
		User:          cred.User,
		Pass:          cred.Pass,
		Token:         cred.Token,
		RepoAuth:      cred.RepoAuth,
		ReqPerSec:     float64(cred.ReqPerSec),
		ReqConcurrent: int64(cred.ReqConcurrent),
		RegCert:       cred.RegCert,
		ClientCert:    cred.ClientCert,
		ClientKey:     cred.ClientKey,
		CredHelper:    cred.CredHelper,
		PathPrefix:    cred.PathPrefix,
		Scheme:        cred.Scheme,
	}
	if cred.TLS != "" {
		if err := host.TLS.UnmarshalText([]byte(cred.TLS)); err != nil {
			return host, fmt.Errorf("creds tls for %s: %w", cred.Registry, err)
		}
	}
	return host, nil
}
