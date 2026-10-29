package mirror

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	rtemplate "github.com/regclient/regclient/pkg/template"
	"github.com/regclient/regclient/scheme"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"

	"github.com/daimoniac/suppline/internal/config"
)

type action int

const (
	actionCopy action = iota
	actionMissing
)

func (m *runner) process(ctx context.Context, s config.SyncEntry, act action) error {
	switch s.Type {
	case "registry":
		return m.processRegistry(ctx, s, s.Source, s.Target, act)
	case "repository":
		return m.processRepo(ctx, s, s.Source, s.Target, act)
	case "image":
		return m.processImage(ctx, s, s.Source, s.Target, act)
	default:
		m.log.Error("type not recognized, must be registry, repository, or image",
			"source", s.Source, "target", s.Target, "type", s.Type)
		return fmt.Errorf("invalid sync type %q", s.Type)
	}
}

func (m *runner) processRegistry(ctx context.Context, s config.SyncEntry, src, tgt string, act action) error {
	last := ""
	var errs []error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var repoOpts []scheme.RepoOpts
		if last != "" {
			repoOpts = append(repoOpts, scheme.WithRepoLast(last))
		}
		sRepos, err := m.rc.RepoList(ctx, src, repoOpts...)
		if err != nil {
			m.log.Error("failed to list source repositories", "source", src, "error", err.Error())
			return err
		}
		sRepoList, err := sRepos.GetRepos()
		if err != nil {
			m.log.Error("failed to list source repositories", "source", src, "error", err.Error())
			return err
		}
		if len(sRepoList) == 0 || last == sRepoList[len(sRepoList)-1] {
			break
		}
		last = sRepoList[len(sRepoList)-1]
		sRepoList, err = filterRepoList(s.Repos, sRepoList)
		if err != nil {
			m.log.Error("failed processing repo filters", "source", src, "error", err.Error())
			return err
		}
		for _, repo := range sRepoList {
			if err := m.processRepo(ctx, s, src+"/"+repo, tgt+"/"+repo, act); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (m *runner) processRepo(ctx context.Context, s config.SyncEntry, src, tgt string, act action) error {
	sRepoRef, err := ref.New(src)
	if err != nil {
		m.log.Error("failed parsing source", "source", src, "error", err.Error())
		return err
	}
	sTags, err := m.rc.TagList(ctx, sRepoRef)
	if err != nil {
		m.log.Error("failed getting source tags", "source", sRepoRef.CommonName(), "error", err.Error())
		return err
	}
	sTagsList, err := sTags.GetTags()
	if err != nil {
		m.log.Error("failed getting source tags", "source", sRepoRef.CommonName(), "error", err.Error())
		return err
	}
	sets := entryTagSets(s)
	sTagsFiltered := []string{}
	if len(sets) == 0 {
		sTagsFiltered = sTagsList
	}
	for _, set := range sets {
		filtered, ferr := filterTagList(set, sTagsList)
		if ferr != nil {
			m.log.Error("failed processing tag filters", "source", sRepoRef.CommonName(), "error", ferr.Error())
			return ferr
		}
		for _, tag := range filtered {
			if !slices.Contains(sTagsFiltered, tag) {
				sTagsFiltered = append(sTagsFiltered, tag)
			}
		}
	}
	if len(sTagsFiltered) == 0 {
		m.log.Warn("no matching tags found", "source", sRepoRef.CommonName())
		return nil
	}
	if act == actionMissing {
		sTagsFiltered, err = dropExistingTags(ctx, m, tgt, sTagsFiltered)
		if err != nil {
			return err
		}
	}
	var errs []error
	for _, tag := range sTagsFiltered {
		if err := m.processImage(ctx, s, src+":"+tag, tgt+":"+tag, act); err != nil {
			errs = append(errs, err)
		}
	}
	if act == actionCopy && s.CleanupTags != nil && *s.CleanupTags {
		if err := m.cleanupTags(ctx, tgt); err != nil {
			m.log.Error("failed to cleanup tags", "target", tgt, "error", err.Error())
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func dropExistingTags(ctx context.Context, m *runner, tgt string, source []string) ([]string, error) {
	tRepoRef, err := ref.New(tgt)
	if err != nil {
		m.log.Error("failed parsing target", "target", tgt, "error", err.Error())
		return nil, err
	}
	tTags, err := m.rc.TagList(ctx, tRepoRef)
	if err != nil {
		m.log.Debug("failed getting target tags", "target", tRepoRef.CommonName(), "error", err.Error())
		return source, nil
	}
	tTagList, err := tTags.GetTags()
	if err != nil {
		m.log.Debug("failed getting target tags", "target", tRepoRef.CommonName(), "error", err.Error())
		return source, nil
	}
	slices.Sort(source)
	slices.Sort(tTagList)
	sI := len(source) - 1
	tI := len(tTagList) - 1
	for sI >= 0 && tI >= 0 {
		switch strings.Compare(source[sI], tTagList[tI]) {
		case 0:
			source = slices.Delete(source, sI, sI+1)
			sI--
			tI--
		case -1:
			tI--
		default:
			sI--
		}
	}
	return source, nil
}

func (m *runner) processImage(ctx context.Context, s config.SyncEntry, src, tgt string, act action) error {
	sRef, err := ref.New(src)
	if err != nil {
		m.log.Error("failed parsing source", "source", src, "error", err.Error())
		return err
	}
	tRef, err := ref.New(tgt)
	if err != nil {
		m.log.Error("failed parsing target", "target", tgt, "error", err.Error())
		return err
	}
	err = m.processRef(ctx, s, sRef, tRef, act)
	if err != nil {
		m.log.Error("failed to sync", "target", tRef.CommonName(), "source", sRef.CommonName(), "error", err.Error())
	}
	if cerr := m.rc.Close(ctx, tRef); cerr != nil {
		m.log.Error("error closing ref", "ref", tRef.CommonName(), "error", cerr.Error())
	}
	return err
}

func (m *runner) processRef(ctx context.Context, s config.SyncEntry, src, tgt ref.Ref, act action) error {
	mSrc, err := m.rc.ManifestHead(ctx, src, regclient.WithManifestRequireDigest())
	if err != nil && errors.Is(err, errs.ErrUnsupportedAPI) {
		mSrc, err = m.rc.ManifestGet(ctx, src)
	}
	if err != nil {
		m.log.Error("failed to lookup source manifest", "source", src.CommonName(), "error", err.Error())
		return err
	}
	fastCheck := s.FastCheck != nil && *s.FastCheck
	forceRecursive := s.ForceRecursive != nil && *s.ForceRecursive
	referrers := s.Referrers != nil && *s.Referrers
	digestTags := s.DigestTags != nil && *s.DigestTags
	mTgt, err := m.rc.ManifestHead(ctx, tgt, regclient.WithManifestRequireDigest())
	tgtExists := err == nil
	tgtMatches := false
	if err == nil && manifest.GetDigest(mSrc).String() == manifest.GetDigest(mTgt).String() {
		tgtMatches = true
	}
	if tgtMatches && (fastCheck || (!forceRecursive && !referrers && !digestTags)) {
		m.log.Debug("image matches", "source", src.CommonName(), "target", tgt.CommonName())
		return runHook(ctx, m.log, s.Hooks.Unchanged, "unchanged", src, tgt)
	}
	if tgtExists && act == actionMissing {
		m.log.Debug("target exists", "source", src.CommonName(), "target", tgt.CommonName())
		return nil
	}
	if !slices.Contains(s.MediaTypes, manifest.GetMediaType(mSrc)) {
		m.log.Info("skipping unsupported media type",
			"ref", src.CommonName(),
			"mediaType", manifest.GetMediaType(mSrc),
			"allowed", s.MediaTypes)
		return nil
	}
	if mSrc.IsList() && s.Platform != "" {
		platDigest, perr := m.getPlatformDigest(ctx, src, s.Platform, mSrc)
		if perr != nil {
			return perr
		}
		src.Digest = platDigest.String()
		if tgtExists && platDigest.String() == manifest.GetDigest(mTgt).String() {
			tgtMatches = true
		}
		if tgtMatches && (s.ForceRecursive == nil || !*s.ForceRecursive) {
			m.log.Debug("image matches for platform", "source", src.CommonName(), "platform", s.Platform, "target", tgt.CommonName())
			return runHook(ctx, m.log, s.Hooks.Unchanged, "unchanged", src, tgt)
		}
	}
	if tgtMatches {
		m.log.Info("image refreshing", "source", src.CommonName(), "target", tgt.CommonName(),
			"forced", forceRecursive, "digestTags", digestTags, "referrers", referrers)
	} else {
		m.log.Info("image sync needed", "source", src.CommonName(), "target", tgt.CommonName())
	}

	priority := 0
	if act == actionMissing {
		priority = 1
	}
	release, err := m.throttle.Acquire(ctx, priority)
	if err != nil {
		return fmt.Errorf("acquire throttle: %w", err)
	}
	if s.RateLimit.Min > 0 && manifest.GetRateLimit(mSrc).Set {
		mSrc, err = m.rc.ManifestHead(ctx, src)
		if err != nil {
			m.log.Error("rate limit check failed", "source", src.CommonName(), "error", err.Error())
			release()
			return err
		}
		rlSrc := manifest.GetRateLimit(mSrc)
		for rlSrc.Remain < s.RateLimit.Min {
			release()
			m.log.Info("delaying for rate limit",
				"source", src.CommonName(),
				"remain", rlSrc.Remain,
				"limit", rlSrc.Limit,
				"min", s.RateLimit.Min,
				"sleep", s.RateLimit.Retry.String())
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.RateLimit.Retry.Std()):
			}
			release, err = m.throttle.Acquire(ctx, priority)
			if err != nil {
				return fmt.Errorf("reacquire throttle: %w", err)
			}
			mSrc, err = m.rc.ManifestHead(ctx, src)
			if err != nil {
				m.log.Error("rate limit check failed", "source", src.CommonName(), "error", err.Error())
				release()
				return err
			}
			rlSrc = manifest.GetRateLimit(mSrc)
		}
	}
	defer release()

	if err := ctx.Err(); err != nil {
		return err
	}
	if tgtExists && !tgtMatches && s.Backup != "" {
		if err := m.backup(ctx, s, tgt); err != nil {
			return err
		}
	}
	if err := runHook(ctx, m.log, s.Hooks.Pre, "pre", src, tgt); err != nil {
		return err
	}
	rcOpts := imageOpts(m, s)
	m.log.Debug("image sync running", "source", src.CommonName(), "target", tgt.CommonName())
	if err := m.rc.ImageCopy(ctx, src, tgt, rcOpts...); err != nil {
		m.log.Error("failed to copy image", "source", src.CommonName(), "target", tgt.CommonName(), "error", err.Error())
		return err
	}
	return runHook(ctx, m.log, s.Hooks.Post, "post", src, tgt)
}

func (m *runner) backup(ctx context.Context, s config.SyncEntry, tgt ref.Ref) error {
	data := struct {
		Ref  ref.Ref
		Step config.SyncEntry
		Sync config.SyncEntry
	}{Ref: tgt, Step: s, Sync: s}
	backupStr, err := rtemplate.String(s.Backup, data)
	if err != nil {
		m.log.Error("failed to expand backup template", "original", tgt.CommonName(), "backup-template", s.Backup, "error", err.Error())
		return err
	}
	backupStr = strings.TrimSpace(backupStr)
	backupRef := tgt
	if strings.ContainsAny(backupStr, ":/") {
		backupRef, err = ref.New(backupStr)
		if err != nil {
			m.log.Error("failed to parse backup reference", "original", tgt.CommonName(), "backup", backupStr, "error", err.Error())
			return err
		}
	} else {
		backupRef = backupRef.SetTag(backupStr)
	}
	defer m.rc.Close(ctx, backupRef)
	m.log.Info("saving backup", "original", tgt.CommonName(), "backup", backupRef.CommonName())
	if err := m.rc.ImageCopy(ctx, tgt, backupRef); err != nil {
		m.log.Warn("failed to backup existing image", "original", tgt.CommonName(), "backup", backupRef.CommonName(), "error", err.Error())
	}
	return nil
}

func imageOpts(m *runner, s config.SyncEntry) []regclient.ImageOpts {
	var rcOpts []regclient.ImageOpts
	if s.DigestTags != nil && *s.DigestTags {
		rcOpts = append(rcOpts, regclient.ImageWithDigestTags())
	}
	if s.Referrers != nil && *s.Referrers {
		if len(s.ReferrerFilters) == 0 {
			rcOpts = append(rcOpts, regclient.ImageWithReferrers())
		} else {
			for _, filter := range s.ReferrerFilters {
				var rOpts []scheme.ReferrerOpts
				if filter.ArtifactType != "" {
					rOpts = append(rOpts, scheme.WithReferrerMatchOpt(descriptor.MatchOpt{ArtifactType: filter.ArtifactType}))
				}
				if filter.Annotations != nil {
					rOpts = append(rOpts, scheme.WithReferrerMatchOpt(descriptor.MatchOpt{Annotations: filter.Annotations}))
				}
				if s.ReferrerSlow != nil && *s.ReferrerSlow {
					rOpts = append(rOpts, scheme.WithReferrerSlowSearch())
				}
				rcOpts = append(rcOpts, regclient.ImageWithReferrers(rOpts...))
			}
		}
		if s.ReferrerSrc != "" {
			referrerSrc, err := ref.New(s.ReferrerSrc)
			if err != nil {
				m.log.Error("failed to parse referrer source reference", "referrerSource", s.ReferrerSrc, "error", err.Error())
			}
			rcOpts = append(rcOpts, regclient.ImageWithReferrerSrc(referrerSrc))
		}
		if s.ReferrerTgt != "" {
			referrerTgt, err := ref.New(s.ReferrerTgt)
			if err != nil {
				m.log.Error("failed to parse referrer target reference", "referrerTarget", s.ReferrerTgt, "error", err.Error())
			}
			rcOpts = append(rcOpts, regclient.ImageWithReferrerTgt(referrerTgt))
		}
	}
	if s.FastCheck != nil && *s.FastCheck {
		rcOpts = append(rcOpts, regclient.ImageWithFastCheck())
	}
	if s.ForceRecursive != nil && *s.ForceRecursive {
		rcOpts = append(rcOpts, regclient.ImageWithForceRecursive())
	}
	if s.IncludeExternal != nil && *s.IncludeExternal {
		rcOpts = append(rcOpts, regclient.ImageWithIncludeExternal())
	}
	if len(s.Platforms) > 0 {
		rcOpts = append(rcOpts, regclient.ImageWithPlatforms(s.Platforms))
	}
	return rcOpts
}

func (m *runner) getPlatformDigest(ctx context.Context, r ref.Ref, platStr string, origMan manifest.Manifest) (digest.Digest, error) {
	plat, err := platform.Parse(platStr)
	if err != nil {
		m.log.Warn("could not parse platform", "platform", platStr, "error", err.Error())
		return "", err
	}
	key := manifest.GetDigest(origMan).String()
	m.manifestMu.Lock()
	getMan, ok := m.manifests[key]
	if !ok {
		getMan, err = m.rc.ManifestGet(ctx, r)
		if err != nil {
			m.manifestMu.Unlock()
			m.log.Error("failed to get source manifest", "source", r.CommonName(), "error", err.Error())
			return "", err
		}
		m.manifests[key] = getMan
	}
	m.manifestMu.Unlock()
	descPlat, err := manifest.GetPlatformDesc(getMan, &plat)
	if err != nil {
		pl, _ := manifest.GetPlatformList(getMan)
		names := make([]string, 0, len(pl))
		for _, p := range pl {
			names = append(names, p.String())
		}
		m.log.Warn("platform could not be found in source manifest list",
			"platform", plat.String(), "error", err.Error(), "platforms", strings.Join(names, ", "))
		return "", errs.ErrNotFound
	}
	return descPlat.Digest, nil
}
