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
///
/// fix/home-pull-jank (v0.19.21 「首页下拉卡顿的问题在这个版本中又出现了」): scroll tracking never writes view
/// state. The probe's per-frame offset goes into `PinnedHeaderScrollTracker`, a plain reference held in @State
/// (not observed by this modifier), which publishes only what changed: the thresholded `scrolled` flag and the
/// pixel-rounded overscroll, each on its own tiny observable read by one small subview (bar background +
/// hairline, and the offset wrapper). Before, `probeY` / `headerBottom` were @State here, so every scroll frame
/// re-ran this body (title, header closure, materials, two GeometryReaders), and during a pull the header's
/// GeometryReader — measured inside the `.offset` — wrote `headerBottom` again on every frame from a value that
/// already contained the offset (a63b9c9 「always tracking」), a second state write per frame that could chase the
/// next frame's offset. The header bottom is now measured on a container outside the offset (layout space),
/// so riding down with the pull cannot feed back into it.
struct TabRootPinnedChrome<Header: View>: ViewModifier {
    let title: LocalizedStringKey
    let header: () -> Header
    /// Held, not observed: this body does not re-run while scrolling.
    @State private var tracker = PinnedHeaderScrollTracker()

    func body(content: Content) -> some View {
        let tracker = tracker
        return content
            .navigationTitle(title)
            .toolbar(.hidden, for: .navigationBar)
            .onPreferenceChange(TabRootScrollKey.self) { tracker.probeMoved(to: $0) }
            .safeAreaInset(edge: .top, spacing: 0) {
                // The offset wrapper is the only view that re-renders per pull frame; the header inside it is
                // built once here and compares equal, so its body (exit IP, switch) is not re-evaluated.
                PinnedOverscrollOffset(overscroll: tracker.overscroll) {
                    VStack(spacing: 0) {
                        // Egern-style page title, same height as the other tabs' inline bar row.
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
                        PinnedHeaderHairline(scrolled: tracker.scrolled)
                    }
                    .background(PinnedHeaderBackground(scrolled: tracker.scrolled))
                }
                // Layout space: this container is not offset (the offset is applied inside it), so the value
                // only changes when the header's height really changes (Dynamic Type, exit IP line).
                .background(GeometryReader { g in
                    Color.clear
                        .onAppear { tracker.headerMoved(to: g.frame(in: .global).maxY) }
                        .onChange(of: g.frame(in: .global).maxY) { tracker.headerMoved(to: $0) }
                })
            }
    }
}

/// fix/home-pull-jank: the pinned header's scroll state, outside SwiftUI's view state. Fed every scroll frame by
/// the probe; publishes only on change — `scrolled` when it crosses the header bottom, `overscroll` only while
/// pulled down past the rest position (rounded to whole pixels), never during an ordinary scroll.
final class PinnedHeaderScrollTracker {
    final class Flag: ObservableObject { @Published fileprivate(set) var value = false }
    final class Offset: ObservableObject { @Published fileprivate(set) var value: CGFloat = 0 }

    let scrolled = Flag()
    let overscroll = Offset()
    private(set) var probeY: CGFloat = .greatestFiniteMagnitude
    private(set) var headerBottom: CGFloat = 0
    private let pixel: CGFloat

    init(pixel: CGFloat = 1 / max(UIScreen.main.scale, 1)) { self.pixel = pixel }

    /// The scroll content's top edge (global minY), every frame while scrolling.
    func probeMoved(to y: CGFloat) {
        probeY = y
        recompute()
    }

    /// The pinned header's bottom in layout space (not including the overscroll offset).
    func headerMoved(to y: CGFloat) {
        guard abs(y - headerBottom) >= 0.5 else { return }
        headerBottom = y
        recompute()
    }

    private func recompute() {
        let known = probeY != .greatestFiniteMagnitude && headerBottom > 0
        let s = known && probeY < headerBottom - 0.5
        if s != scrolled.value { scrolled.value = s }
        var o: CGFloat = known ? max(0, probeY - headerBottom) : 0
        o = (o / pixel).rounded() * pixel
        if o != overscroll.value { overscroll.value = o }
    }
}

/// Rides the pinned header down with a pull (8da2e32). Observes only the overscroll value.
struct PinnedOverscrollOffset<Content: View>: View {
    @ObservedObject var overscroll: PinnedHeaderScrollTracker.Offset
    let content: Content

    init(overscroll: PinnedHeaderScrollTracker.Offset, @ViewBuilder content: () -> Content) {
        self.overscroll = overscroll
        self.content = content()
    }

    var body: some View {
        content.offset(y: overscroll.value)
    }
}

/// Page colour at rest, bar material once content scrolls under the header. Observes only the scrolled flag.
struct PinnedHeaderBackground: View {
    @ObservedObject var scrolled: PinnedHeaderScrollTracker.Flag

    var body: some View {
        ZStack {
            Theme.bg.opacity(scrolled.value ? 0 : 1)
            Rectangle().fill(.bar).opacity(scrolled.value ? 1 : 0)
        }
        .animation(.easeInOut(duration: 0.15), value: scrolled.value)
        .ignoresSafeArea(edges: .top)
        .accessibilityHidden(true)
    }
}

struct PinnedHeaderHairline: View {
    @ObservedObject var scrolled: PinnedHeaderScrollTracker.Flag

    var body: some View {
        Rectangle()
            .fill(Color(uiColor: .separator))
            .frame(height: 1 / UIScreen.main.scale)
            .opacity(scrolled.value ? 1 : 0)
            .animation(.easeInOut(duration: 0.15), value: scrolled.value)
            .accessibilityHidden(true)
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
