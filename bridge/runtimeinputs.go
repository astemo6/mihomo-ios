package libmihomo

// runtimeInputFiles is THE list of files the runtime build (readRuntimeProfile → overridesFor →
// buildRuntimeWith) reads or stats. runtimeCacheKey signs exactly this list, so the node-manager runtime
// cache can never serve a runtime built from stale inputs.
//
// r7 (review: provider-overrides.json was missing — the 4th time a new build input was added without the
// cache key): a new file read during the build MUST be added here. TestRuntimeInputFilesCoverBuildReads
// walks the build's call graph and fails on any os.ReadFile / os.Stat it cannot match to this list.

import (
	"path/filepath"
	"sort"
)

func overridesPath(home string) string   { return filepath.Join(home, "overrides.json") }
func dnsOverridePath(home string) string { return filepath.Join(home, "dns.json") }
func localDNSPath(home string) string    { return filepath.Join(home, "localdns.json") }
func customRulesPath(home string) string { return filepath.Join(home, "rules.json") }
func manualNodesPath(home string) string {
	return filepath.Join(filepath.Dir(home), "profiles", "manual-nodes.yaml")
}
func nodeSubBodiesGlob(home string) string  { return filepath.Join(home, "nodesubs", "*") }
func providerBodiesGlob(home string) string { return filepath.Join(home, "proxies", "*") }
func ownPolicySidecarGlob(home string) string {
	return filepath.Join(home, "ruleset", "*.policies.json")
}

func runtimeInputFiles(home, profilePath string) []string {
	yp, mp := scriptedPaths(home, profilePath)
	l := []string{
		profilePath,
		yp, mp, // 覆写脚本 output readRuntimeProfile prefers (scriptedFor)
		overridesPath(home),         // readOverrides
		secretsPath(home),           // readOverrides → readSecrets (r7 B01)
		dnsOverridePath(home),       // readOverrides → readDNSOverride
		localDNSPath(home),          // readOverrides → readLocalDNS
		manualNodesPath(home),       // mergeManualNodes
		subRulesPath(home),          // overridesFor → readAllSubRules
		groupSettingsPath(home),     // overridesFor → readGroupChains
		groupEditsPath(home),        // buildRuntimeWith → readGroupEdits
		customRulesPath(home),       // applyCustomRules
		providerOverridesPath(home), // buildRuntimeWith → readProviderOverrides
		nodeSubsPath(home),          // mergeNodeSubs → readNodeSubs
		proxyChainsPath(home),       // buildRuntimeWith → readProxyChains (代理链)
	}
	// Node-subscription bodies: mergeNodeSubs stats each listed one (skips missing/empty); the whole
	// nodesubs/ directory is signed so a re-download (new content) also changes the key, as do the
	// downloaded proxy-provider bodies in proxies/ that the node manager reads next to the runtime.
	for _, s := range readNodeSubs(home) {
		if s.ID != "" {
			l = append(l, NodeSubPath(home, s.ID))
		}
	}
	for _, g := range []string{nodeSubBodiesGlob(home), providerBodiesGlob(home)} {
		if m, _ := filepath.Glob(g); len(m) > 0 {
			sort.Strings(m)
			l = append(l, m...)
		}
	}
	// expandOwnPolicyProviders reads <provider cache>.policies.json; the importer puts those caches in
	// ./ruleset/ (confimport list-own providers).
	if m, _ := filepath.Glob(ownPolicySidecarGlob(home)); len(m) > 0 {
		sort.Strings(m)
		l = append(l, m...)
	}
	return l
}
