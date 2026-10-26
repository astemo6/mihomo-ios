import Foundation

/// nc-integrate B5/B6: the retired bridge + ModuleUnresolved in Swift — the active profile's
/// group names and the policies a module's [Rule] lines use that the profile lacks (模块策略映射).
/// bridge profileRaw = the runtime tree built with the profile's attachments but no home (no custom rules);
/// mitm ProfileNames / ResolveCoreRules / Ruleset.ParseText are the #111/#112 ports.
enum NCModulePolicies {

    /// bridge profileRaw.
    static func profileRaw(home: String, profilePath: String) -> [String: NCJSONValue] {
        guard let b = NCRuntimeFiles.readRuntimeProfile(home: home, path: profilePath, safe: false) else { return [:] }
        var req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
        req.settings.home = "" // the old core: o.home = "" — don't recurse into custom rules
        return (try? NCRuntimeBuilder.build(profile: b, req: req, fd: 0))?.raw ?? [:]
    }

    /// bridge ProfileGroups.
    static func profileGroups(home: String, profilePath: String) -> [String] {
        NCRuntimeSteps.profileNames(profileRaw(home: home, profilePath: profilePath)).groups
    }

    /// Both for one view load, sharing one runtime build (the old core built the tree twice).
    static func load(home: String, profilePath: String, moduleText: String, args: [String: String]) -> (unresolved: [String], groups: [String]) {
        let raw = profileRaw(home: home, profilePath: profilePath)
        let rs = NCEngineRuleset()
        rs.parseText(moduleText, source: "模块", args: args)
        var un: Set<String>? = []
        _ = NCRuntimeSteps.resolveCoreRules(raw, rules: rs.coreRules, unresolved: &un)
        return (Array(un ?? []), NCRuntimeSteps.profileNames(raw).groups)
    }
}
