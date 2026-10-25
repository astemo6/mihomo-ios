import Foundation

// MARK: - Tailscale DERP Map & Node Models (tailcfg JSON)
//
// Pure Swift Codable models matching the official Tailscale `tailcfg.DERPMap` JSON specification.
// Reference: `tailscale.com/tailcfg.DERPMap`, `tailscale.com/tailcfg.DERPRegion`, `tailscale.com/tailcfg.DERPNode`.
//
// Models for DERPMap, DERPRegion, and DERPNode are consolidated in `NCTailscaleControlModels.swift`
// as the canonical source of truth for the entire Network Extension target.
// The typealiases below ensure backwards compatibility with Stage 3a components.

// MARK: - Compatibility Typealiases

public typealias DERPNode = NCTailscaleDERPNode
public typealias DERPRegion = NCTailscaleDERPRegion
public typealias DERPMap = NCTailscaleDERPMap
