import SwiftUI

/// A NavigationLink builds its destination as soon as the link is built, so every render of a list of
/// links runs each destination's init (and its `@State … = X.load()` initial values). Wrapping the
/// destination defers that until the page is actually pushed (review 5, P2-2).
struct LazyDestination<Content: View>: View {
    let build: () -> Content
    init(@ViewBuilder _ build: @escaping () -> Content) { self.build = build }
    var body: some View { build() }
}
