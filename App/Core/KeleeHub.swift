import Foundation

// 模块库 → 可莉插件中心 (feat/kelee-hub, 「重写插件能帮我做个这个吗？接入可莉插件中心」).
//
// hub.kelee.one is Kelee's Loon plugin center. Its page loads one JSON index, https://hub.kelee.one/list.json:
//   { "name", "notice": [..], "banners": [..], "lists": [{ name, desc, tag: [..], icon, date,
//     url: "loon://import?plugin=https://kelee.one/Tool/Loon/Lpx/<name>.lpx", author: [{ name, homepage }] }] }
// ModuleGallery's generic JSON reader handles it (lists → items, first tag → category, author names, the loon://
// install link → the plugin URL); this file only names the source. The plugins are Loon .lpx files in Loon's
// 3.5.1 expression syntax and go through the same generic Loon parser as every other module (bridge
// mitm/loonv2); lines Tern cannot run show under 暂不支持 in the preview, as for any module.
// hub.kelee.one / kelee.one answer browsers and unknown User-Agents with a Cloudflare challenge (HTTP 403);
// the gallery, preview and resource downloads already send a proxy client's User-Agent ("Surge iOS/3000").

enum KeleeHub {
    static let sourceID = "kelee"
    static let indexURL = "https://hub.kelee.one/list.json"
    static let homepage = "https://hub.kelee.one"
    /// Set once the source was added to an existing source list (a later removal by the user sticks).
    static let offeredKey = "moduleGallery.keleeOffered"

    static var source: GallerySource { GallerySource(id: sourceID, name: "可莉插件中心", url: indexURL) }
    static var displayName: String { String(localized: "可莉插件中心") }
}
