import SwiftUI
import UIKit

/// Lightweight code editor (UITextView + regex highlighter, no dependencies) for scripts, profiles and the
/// local module's text view. Highlighting is incremental: after an edit only the touched paragraphs are
/// re-coloured (whole text when small), so large profiles stay responsive.
enum CodeLanguage {
    case javascript, yaml, conf
    /// feat/nc-conf-native: Tern's own profile .conf (Quantumult X style sections), coloured like the YAML profile
    /// editor was: comments, [section] headers, quoted values, keys, policies / rule types, numbers.
    case ternConf

    /// One alternation per language; the first group that matches wins, scanning left to right, so a
    /// "//" inside a string literal is never taken for a comment.
    var regex: NSRegularExpression {
        switch self {
        case .javascript: return Self.js
        case .yaml: return Self.yml
        case .conf: return Self.cnf
        case .ternConf: return Self.tcf
        }
    }

    /// Colour per capture group (1-based).
    var colors: [UIColor] {
        switch self {
        case .javascript: return [CodeTheme.comment, CodeTheme.string, CodeTheme.keyword, CodeTheme.api, CodeTheme.number]
        case .yaml: return [CodeTheme.comment, CodeTheme.string, CodeTheme.key, CodeTheme.number, CodeTheme.keyword]
        case .conf: return [CodeTheme.comment, CodeTheme.section, CodeTheme.string, CodeTheme.keyword, CodeTheme.api]
        case .ternConf: return [CodeTheme.comment, CodeTheme.section, CodeTheme.string, CodeTheme.key, CodeTheme.keyword, CodeTheme.number]
        }
    }

    private static let jsKeywords = "break|case|catch|class|const|continue|default|delete|do|else|export|extends|finally|for|function|if|import|in|instanceof|let|new|of|return|switch|this|throw|try|typeof|var|void|while|yield|async|await|true|false|null|undefined"
    private static let js = try! NSRegularExpression(pattern:
        #"(//[^\n]*|/\*[\s\S]*?(?:\*/|$))|("(?:\\.|[^"\\\n])*"?|'(?:\\.|[^'\\\n])*'?|`(?:\\.|[^`\\])*`?)|\b("# + jsKeywords + #")\b|(\$[A-Za-z_][A-Za-z0-9_]*|\bctx\b|\bconsole\b)|(\b\d+(?:\.\d+)?\b)"#,
        options: [])
    private static let yml = try! NSRegularExpression(pattern:
        #"((?:^|(?<=\s))#[^\n]*)|("(?:\\.|[^"\\\n])*"?|'[^'\n]*'?)|(^[ \t]*(?:- +)?[^\s#'"\-][^:#\n]*?:(?=[ \t]|$))|(\b(?:true|false|null|yes|no)\b|(?<![\w.])-?\d+(?:\.\d+)?\b)|(\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b|\b(?:DOMAIN|GEOIP|GEOSITE|MATCH|FINAL|DIRECT|REJECT|AND|OR|NOT)\b)"#,
        options: [.anchorsMatchLines])
    private static let tcf = try! NSRegularExpression(pattern:
        #"((?:^|(?<=\s))(?:#|;|//)[^\n]*)|(^[ \t]*\[[^\]\n]+\][ \t]*$)|("(?:\\.|[^"\\\n])*"?)|((?:^[ \t]*|(?<=,)[ \t]*)[A-Za-z][A-Za-z0-9_.\-]*(?=[ \t]*=))|(\b(?:direct|reject(?:-[a-z0-9]+)*|DIRECT|REJECT(?:-DROP)?|final|host(?:-suffix|-keyword|-wildcard)?|ip6?-cidr|ip-asn|geoip|geosite|rule-set|user-agent|true|false)\b)|((?<![\w.])-?\d+(?:\.\d+)?\b)"#,
        options: [.anchorsMatchLines])
    private static let cnf = try! NSRegularExpression(pattern:
        #"((?:^|(?<=\s))(?:#|;|//)[^\n]*)|(^[ \t]*\[[^\]\n]+\])|("(?:\\.|[^"\\\n])*"?)|(\b(?:reject(?:-[a-z0-9]+)?|302|307|header-(?:add|del|replace(?:-regex)?)|http-(?:request|response)(?:-jq)?|data-type|data|status-code|hostname|url|script-path|type|pattern|requires-body)\b)|(\^[^\s]*)"#,
        options: [.anchorsMatchLines])
}

enum CodeTheme {
    // v0.9: light / dark pairs (dark = the original One-Dark-ish palette, light = same hues for white).
    static func dyn(_ l: UIColor, _ d: UIColor) -> UIColor { UIColor { $0.userInterfaceStyle == .dark ? d : l } }
    static func c(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> UIColor { UIColor(red: r, green: g, blue: b, alpha: a) }
    static let text = dyn(UIColor(white: 0.12, alpha: 1), UIColor(white: 0.90, alpha: 1))
    static let comment = dyn(c(0.42, 0.46, 0.52), c(0.45, 0.50, 0.56))
    static let string = dyn(c(0.72, 0.38, 0.05), c(0.98, 0.72, 0.42))
    static let keyword = dyn(c(0.55, 0.25, 0.80), c(0.78, 0.55, 0.98))
    static let api = dyn(c(0.0, 0.47, 0.78), c(0.29, 0.78, 0.96)) // Theme.accent
    static let number = dyn(c(0.12, 0.55, 0.25), c(0.55, 0.88, 0.60))
    static let key = dyn(c(0.10, 0.40, 0.78), c(0.45, 0.75, 1.0))
    static let section = dyn(c(0.70, 0.45, 0.0), c(1.0, 0.78, 0.2))
    static let errorLine = dyn(c(0.84, 0.19, 0.19, 0.16), c(1.0, 0.36, 0.36, 0.22))
    static let background = dyn(c(1, 1, 1), c(0.04, 0.043, 0.063)) // Theme.card / Theme.bg
}

struct CodeEditor: UIViewRepresentable {
    @Binding var text: String
    var language: CodeLanguage
    var editable: Bool = true
    /// 1-based line to mark as the error (nil = none).
    var errorLine: Int? = nil
    /// Change this value to scroll to `errorLine`.
    var scrollToken: Int = 0

    /// Above this size highlighting is skipped (the editor stays plain and fast).
    static let highlightLimit = 400_000

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeUIView(context: Context) -> UITextView {
        let tv = UITextView()
        context.coordinator.textView = tv
        tv.backgroundColor = CodeTheme.background
        tv.textColor = CodeTheme.text
        tv.font = Coordinator.font
        tv.autocorrectionType = .no
        tv.autocapitalizationType = .none
        tv.smartQuotesType = .no
        tv.smartDashesType = .no
        tv.smartInsertDeleteType = .no
        tv.spellCheckingType = .no
        tv.keyboardType = .asciiCapable
        tv.keyboardDismissMode = .interactive
        tv.alwaysBounceVertical = true
        tv.textContainerInset = UIEdgeInsets(top: 10, left: 8, bottom: 40, right: 8)
        tv.adjustsFontForContentSizeCategory = true
        tv.isEditable = editable
        tv.delegate = context.coordinator
        tv.textStorage.delegate = context.coordinator
        if editable { tv.inputAccessoryView = context.coordinator.accessory(for: tv) }
        tv.text = text
        context.coordinator.highlightAll(tv.textStorage)
        return tv
    }

    func updateUIView(_ tv: UITextView, context: Context) {
        let c = context.coordinator
        c.parent = self
        if tv.text != text {
            let sel = tv.selectedRange
            tv.text = text
            c.highlightAll(tv.textStorage)
            let n = (text as NSString).length
            tv.selectedRange = NSRange(location: min(sel.location, n), length: 0)
        }
        tv.isEditable = editable
        if c.markedLine != errorLine {
            c.mark(line: errorLine, in: tv)
        }
        if c.lastScrollToken != scrollToken {
            c.lastScrollToken = scrollToken
            if let l = errorLine { c.scroll(to: l, in: tv) }
        }
    }

    final class Coordinator: NSObject, UITextViewDelegate, NSTextStorageDelegate {
        var parent: CodeEditor
        var markedLine: Int?
        var markedRange: NSRange?
        var lastScrollToken = 0
        private var inHighlight = false

        static var font: UIFont {
            UIFontMetrics(forTextStyle: .footnote).scaledFont(for: .monospacedSystemFont(ofSize: 13, weight: .regular))
        }

        init(_ p: CodeEditor) { parent = p }

        private var pendingHighlight = false

        func textViewDidChange(_ tv: UITextView) {
            parent.text = tv.text
            // v0.19.3: colours deferred while a CJK / kana input composition was open are applied once it ends.
            if pendingHighlight, tv.markedTextRange == nil {
                pendingHighlight = false
                let ns = (tv.text ?? "") as NSString
                if ns.length < 30_000 {
                    highlightAll(tv.textStorage)
                } else if ns.length <= CodeEditor.highlightLimit {
                    highlight(tv.textStorage, in: ns.paragraphRange(for: NSRange(location: min(tv.selectedRange.location, ns.length), length: 0)))
                }
            }
        }

        // Re-colour the edited paragraphs after every edit.
        func textStorage(_ ts: NSTextStorage, didProcessEditing editedMask: NSTextStorage.EditActions, range editedRange: NSRange, changeInLength delta: Int) {
            guard editedMask.contains(.editedCharacters), !inHighlight else { return }
            let s = ts.string as NSString
            guard s.length <= CodeEditor.highlightLimit else { return }
            // Block comments / template strings can span lines: re-colour everything while small.
            let range = s.length < 30_000 ? NSRange(location: 0, length: s.length) : s.paragraphRange(for: editedRange)
            DispatchQueue.main.async { [weak self, weak ts] in
                guard let self, let ts else { return }
                // v0.19.3: re-colouring the storage while a pinyin / kana composition is open (marked text) can
                // interrupt the input method; wait until the composition is committed.
                if let tv = self.textView, tv.markedTextRange != nil { self.pendingHighlight = true; return }
                self.highlight(ts, in: range)
            }
        }

        func highlightAll(_ ts: NSTextStorage) {
            highlight(ts, in: NSRange(location: 0, length: (ts.string as NSString).length))
        }

        func highlight(_ ts: NSTextStorage, in r: NSRange) {
            let len = (ts.string as NSString).length
            let range = NSIntersectionRange(r, NSRange(location: 0, length: len))
            guard range.length > 0 || len == 0 else { return }
            inHighlight = true
            defer { inHighlight = false }
            ts.beginEditing()
            ts.addAttributes([.foregroundColor: CodeTheme.text, .font: Self.font], range: range)
            if len <= CodeEditor.highlightLimit {
                let colors = parent.language.colors
                parent.language.regex.enumerateMatches(in: ts.string, options: [], range: range) { m, _, _ in
                    guard let m else { return }
                    for g in 1..<m.numberOfRanges where m.range(at: g).location != NSNotFound {
                        if g - 1 < colors.count { ts.addAttribute(.foregroundColor, value: colors[g - 1], range: m.range(at: g)) }
                        break
                    }
                }
            }
            ts.endEditing()
        }

        /// NSRange of a 1-based line.
        func range(ofLine line: Int, in s: NSString) -> NSRange? {
            guard line >= 1 else { return nil }
            var current = 1
            var loc = 0
            while current < line {
                let r = s.range(of: "\n", options: [], range: NSRange(location: loc, length: s.length - loc))
                if r.location == NSNotFound { return nil }
                loc = r.location + 1
                current += 1
            }
            return s.lineRange(for: NSRange(location: min(loc, s.length), length: 0))
        }

        func mark(line: Int?, in tv: UITextView) {
            let ts = tv.textStorage
            let s = ts.string as NSString
            inHighlight = true
            defer { inHighlight = false }
            if let old = markedRange, NSMaxRange(old) <= s.length {
                ts.removeAttribute(.backgroundColor, range: old)
            }
            markedRange = nil
            markedLine = line
            if let line, let r = range(ofLine: line, in: s) {
                ts.addAttribute(.backgroundColor, value: CodeTheme.errorLine, range: r)
                markedRange = r
            }
        }

        func scroll(to line: Int, in tv: UITextView) {
            guard let r = range(ofLine: line, in: tv.text as NSString) else { return }
            tv.scrollRangeToVisible(r)
            if tv.isEditable { tv.selectedRange = NSRange(location: r.location, length: 0) }
        }

        // MARK: keyboard accessory (symbols that are slow to reach on the iOS keyboard)

        weak var textView: UITextView?

        func accessory(for tv: UITextView) -> UIView {
            textView = tv
            let bar = UIInputView(frame: CGRect(x: 0, y: 0, width: 320, height: 40), inputViewStyle: .keyboard)
            let scroll = UIScrollView()
            scroll.showsHorizontalScrollIndicator = false
            scroll.translatesAutoresizingMaskIntoConstraints = false
            let stack = UIStackView()
            stack.axis = .horizontal
            stack.spacing = 6
            stack.translatesAutoresizingMaskIntoConstraints = false
            let symbols: [String]
            switch parent.language {
            case .yaml: symbols = ["⇥", "-", ":", "\"", "'", "[", "]", "{", "}", ",", "#", "|", "*"]
            case .ternConf: symbols = ["=", ",", "[", "]", "#", "\"", "/", "-", ".", "*", "^", "|", "(", ")"]
            default: symbols = ["⇥", "{", "}", "(", ")", "[", "]", ";", "=", "\"", "'", "`", "$", ".", "/", "\\", "^", "*"]
            }
            for s in symbols {
                let b = UIButton(type: .system)
                b.setTitle(s, for: .normal)
                b.titleLabel?.font = .monospacedSystemFont(ofSize: 17, weight: .medium)
                b.backgroundColor = UIColor { $0.userInterfaceStyle == .dark ? UIColor(white: 1, alpha: 0.12) : UIColor(white: 0, alpha: 0.08) }
                b.layer.cornerRadius = 6
                b.tintColor = .label
                b.widthAnchor.constraint(greaterThanOrEqualToConstant: 34).isActive = true
                b.addAction(UIAction { [weak self] _ in self?.insert(s == "⇥" ? "  " : s) }, for: .touchUpInside)
                stack.addArrangedSubview(b)
            }
            let done = UIButton(type: .system)
            done.setImage(UIImage(systemName: "keyboard.chevron.compact.down"), for: .normal)
            done.translatesAutoresizingMaskIntoConstraints = false
            done.addAction(UIAction { [weak self] _ in self?.textView?.resignFirstResponder() }, for: .touchUpInside)
            scroll.addSubview(stack)
            bar.addSubview(scroll)
            bar.addSubview(done)
            NSLayoutConstraint.activate([
                done.trailingAnchor.constraint(equalTo: bar.trailingAnchor, constant: -8),
                done.centerYAnchor.constraint(equalTo: bar.centerYAnchor),
                done.widthAnchor.constraint(equalToConstant: 40),
                scroll.leadingAnchor.constraint(equalTo: bar.leadingAnchor, constant: 6),
                scroll.trailingAnchor.constraint(equalTo: done.leadingAnchor, constant: -4),
                scroll.topAnchor.constraint(equalTo: bar.topAnchor, constant: 4),
                scroll.bottomAnchor.constraint(equalTo: bar.bottomAnchor, constant: -4),
                stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor),
                stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor),
                stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor),
                stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor),
                stack.heightAnchor.constraint(equalTo: scroll.frameLayoutGuide.heightAnchor),
            ])
            return bar
        }

        private func insert(_ s: String) {
            guard let tv = textView, tv.isEditable else { return }
            tv.insertText(s)
        }
    }
}
