import SwiftUI

/// fix/tab-top-spacing (user 2026-10-22: the top whitespace differed between the five tabs — 首页 had a compact
/// header, 请求 / 工具 / 更多 an empty bar row above a large title; then 「底部标签栏已经写了页面名」): one shared top for
/// every tab root. No large title on any root — the tab bar already names the page.
///
/// - Standard roots (策略, 请求, 工具, 更多): the same slim inline navigation bar (one 44 pt row right under the status
///   bar on every tab) holding only the page's trailing buttons; a `.searchable` drawer sits right under it. The
///   bar's own material + hairline covers scrolled content, so nothing runs under the clock.
/// - Pinned-header root (首页, Quantumult X style): the system bar is hidden and `header` is pinned in its place with
///   `safeAreaInset(edge: .top)` — same top edge as the other tabs' row, never scrolls away. Page-coloured at rest;
///   once content scrolls under it, bar material + hairline like the system bar. The scroll view reports its offset
///   with `TabRootScrollProbe()` as the first thing in its content.
///
/// In both cases the title stays the navigation title, so VoiceOver announces the page (an invisible header element),
/// UI tests keep finding `app.navigationBars[<title>]` on standard roots, and pushed pages show it on their back
/// button. Pushed sub-pages are untouched and keep their normal inline titles.
///
/// 2026-10-22 evening (user: 「Tern 每页最上方加上标题吧，现在这样太空了，不协调」): the title is drawn again, Egern style —
/// a large title on standard roots (collapsing to the centred inline title on scroll, like Egern's 「分析」), and a
/// bold left-aligned title row above 首页's pinned header.
struct TabRootChrome: ViewModifier {
    let title: LocalizedStringKey
    var showsTitle: Bool = true

    func body(content: Content) -> some View {
        content
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(showsTitle ? .large : .inline)
            .toolbar(.visible, for: .navigationBar)
    }
}

/// The pinned-header variant (首页). See TabRootChrome.
struct TabRootPinnedChrome<Header: View>: ViewModifier {
    let title: LocalizedStringKey
    let header: () -> Header
    @State private var probeY: CGFloat = .greatestFiniteMagnitude
    @State private var headerBottom: CGFloat = 0

    private var scrolled: Bool { probeY < headerBottom - 0.5 }
    /// Pull-down overscroll (rubber band). The header rides down with the content like a system large title,
    /// instead of staying put while the cards pull away and leave a blank gap (user 2026-10-23 screen recording:
    /// 「首页这个动画有问题」).
    private var overscroll: CGFloat {
        guard probeY != .greatestFiniteMagnitude, headerBottom > 0 else { return 0 }
        return max(0, probeY - headerBottom)
    }

    func body(content: Content) -> some View {
        content
            .navigationTitle(title)
            .toolbar(.hidden, for: .navigationBar)
            .onPreferenceChange(TabRootScrollKey.self) { probeY = $0 }
            .safeAreaInset(edge: .top, spacing: 0) {
                VStack(spacing: 0) {
                    // Egern-style centred page title, same height as the other tabs' inline bar row.
                    Text(title)
                        .font(.title.weight(.bold))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 16)
                        .frame(height: 44)
                        .accessibilityAddTraits(.isHeader)
                        .accessibilityIdentifier("tabroot.title")
                    header()
                        .padding(.horizontal, 16)
                        .padding(.top, 0)
                        .padding(.bottom, 8)
                    Rectangle()
                        .fill(Color(uiColor: .separator))
                        .frame(height: 1 / UIScreen.main.scale)
                        .opacity(scrolled ? 1 : 0)
                        .accessibilityHidden(true)
                }
                .background(
                    ZStack {
                        Theme.bg.opacity(scrolled ? 0 : 1)
                        Rectangle().fill(.bar).opacity(scrolled ? 1 : 0)
                    }
                    .ignoresSafeArea(edges: .top)
                    .accessibilityHidden(true)
                )
                .background(GeometryReader { g in
                    // Measured in layout space (before the overscroll offset below), so riding down never feeds
                    // back into headerBottom.
                    Color.clear
                        .onAppear { headerBottom = g.frame(in: .global).maxY }
                        .onChange(of: g.frame(in: .global).maxY) { if overscroll == 0 { headerBottom = $0 } }
                })
                .animation(.easeInOut(duration: 0.15), value: scrolled)
                .offset(y: overscroll)
            }
    }
}

/// Zero-height marker placed first in a pinned-header root's scroll content; reports its global minY.
struct TabRootScrollProbe: View {
    var body: some View {
        GeometryReader { g in
            Color.clear.preference(key: TabRootScrollKey.self, value: g.frame(in: .global).minY)
        }
        .frame(height: 0)
        .accessibilityHidden(true)
    }
}

struct TabRootScrollKey: PreferenceKey {
    static var defaultValue: CGFloat = .greatestFiniteMagnitude
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = min(value, nextValue()) }
}

extension View {
    /// The shared top of a tab root (策略, 请求, 工具, 更多). Keep the page's own `.toolbar` for its buttons.
    func tabRootChrome(_ title: LocalizedStringKey, showsTitle: Bool = true) -> some View {
        modifier(TabRootChrome(title: title, showsTitle: showsTitle))
    }

    /// The shared top of a tab root whose header is pinned in place of the bar (首页).
    func tabRootChrome<H: View>(_ title: LocalizedStringKey, @ViewBuilder pinnedHeader: @escaping () -> H) -> some View {
        modifier(TabRootPinnedChrome(title: title, header: pinnedHeader))
    }
}
